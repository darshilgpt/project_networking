"""TLS Inspector for extracting plaintext ClientHello metadata, SNI, and versioning."""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import struct
from typing import List, Optional, Tuple

# GREASE values (RFC 8701) to ignore for JA3 fingerprint calculation
GREASE_SET = {
    0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A, 0x5A5A, 0x6A6A, 0x7A7A,
    0x8A8A, 0x9A9A, 0xAAAA, 0xBABA, 0xCACA, 0xDADA, 0xEAEA, 0xFAFA,
}

TLS_VERSIONS = {
    0x0300: "SSL 3.0",
    0x0301: "TLS 1.0",
    0x0302: "TLS 1.1",
    0x0303: "TLS 1.2",
    0x0304: "TLS 1.3",
}

TLS_CONTENT_TYPES = {
    20: "ChangeCipherSpec",
    21: "Alert",
    22: "Handshake",
    23: "ApplicationData (Encrypted)",
}

TLS_HANDSHAKE_TYPES = {
    1: "ClientHello",
    2: "ServerHello",
    11: "Certificate",
    12: "ServerKeyExchange",
    14: "ServerHelloDone",
    16: "ClientKeyExchange",
}


@dataclass
class TLSMetadata:
    """Extracted TLS metadata."""
    content_type_code: int
    content_type_name: str
    record_version_code: int
    record_version_name: str
    record_length: int
    is_handshake: bool = False
    handshake_type: Optional[str] = None
    client_version_name: Optional[str] = None
    sni: Optional[str] = None
    cipher_suite_count: int = 0
    cipher_suites: List[int] = field(default_factory=list)
    extensions: List[int] = field(default_factory=list)
    supported_groups: List[int] = field(default_factory=list)
    ec_point_formats: List[int] = field(default_factory=list)
    alpn_protocols: List[str] = field(default_factory=list)
    ja3_string: Optional[str] = None
    ja3_hash: Optional[str] = None
    is_encrypted_application_data: bool = False


class TLSInspector:
    """Inspects TLS records and parses unencrypted handshake metadata."""

    RECORD_HEADER_LEN = 5

    @classmethod
    def is_tls(cls, payload: bytes) -> bool:
        """Checks if payload matches TLS record format."""
        if len(payload) < cls.RECORD_HEADER_LEN:
            return False

        content_type = payload[0]
        version = (payload[1] << 8) | payload[2]

        if content_type in TLS_CONTENT_TYPES and (version in TLS_VERSIONS or (version >> 8) == 3):
            return True

        return False

    @classmethod
    def inspect(cls, payload: bytes) -> Optional[TLSMetadata]:
        """
        Extracts TLS record headers and, if ClientHello, extracts the SNI domain name.

        NOTE:
            Encrypted application data (ContentType 23) cannot be decrypted
            without private keys; it is marked as encrypted data.
        """
        if not cls.is_tls(payload):
            return None

        content_type = payload[0]
        version = struct.unpack("!H", payload[1:3])[0]
        rec_len = struct.unpack("!H", payload[3:5])[0]

        ct_name = TLS_CONTENT_TYPES.get(content_type, f"ContentType_{content_type}")
        ver_name = TLS_VERSIONS.get(version, f"0x{version:04X}")

        is_handshake = content_type == 22
        is_encrypted = content_type == 23

        sni = None
        hs_type_name = None
        client_ver_name = None
        cipher_count = 0
        alpn_list: List[str] = []
        ciphers_list: List[int] = []
        exts_list: List[int] = []
        curves_list: List[int] = []
        points_list: List[int] = []
        ja3_str: Optional[str] = None
        ja3_h: Optional[str] = None

        if is_handshake and len(payload) >= cls.RECORD_HEADER_LEN + 4:
            hs_type = payload[5]
            hs_type_name = TLS_HANDSHAKE_TYPES.get(hs_type, f"Type_{hs_type}")

            # Parse ClientHello (HandshakeType 1)
            if hs_type == 1:
                (
                    sni,
                    client_ver_name,
                    cipher_count,
                    alpn_list,
                    ciphers_list,
                    exts_list,
                    curves_list,
                    points_list,
                    ja3_str,
                    ja3_h,
                ) = cls._parse_client_hello(payload[9:])

        return TLSMetadata(
            content_type_code=content_type,
            content_type_name=ct_name,
            record_version_code=version,
            record_version_name=ver_name,
            record_length=rec_len,
            is_handshake=is_handshake,
            handshake_type=hs_type_name,
            client_version_name=client_ver_name,
            sni=sni,
            cipher_suite_count=cipher_count,
            cipher_suites=ciphers_list,
            extensions=exts_list,
            supported_groups=curves_list,
            ec_point_formats=points_list,
            alpn_protocols=alpn_list,
            ja3_string=ja3_str,
            ja3_hash=ja3_h,
            is_encrypted_application_data=is_encrypted,
        )

    @classmethod
    def _parse_client_hello(
        cls, data: bytes
    ) -> Tuple[
        Optional[str],
        Optional[str],
        int,
        List[str],
        List[int],
        List[int],
        List[int],
        List[int],
        Optional[str],
        Optional[str],
    ]:
        """Parses ClientHello payload to extract SNI, version, ciphers, ALPN, and JA3 fingerprint."""
        offset = 0
        if len(data) < 34:
            return None, None, 0, [], [], [], [], [], None, None

        client_ver = struct.unpack("!H", data[offset : offset + 2])[0]
        client_ver_name = TLS_VERSIONS.get(client_ver, f"0x{client_ver:04X}")
        offset += 34

        # Session ID
        if offset >= len(data):
            return None, client_ver_name, 0, [], [], [], [], [], None, None
        sess_id_len = data[offset]
        offset += 1 + sess_id_len

        # Cipher Suites
        if offset + 2 > len(data):
            return None, client_ver_name, 0, [], [], [], [], [], None, None
        cipher_len = struct.unpack("!H", data[offset : offset + 2])[0]
        cipher_count = cipher_len // 2

        raw_ciphers: List[int] = []
        c_end = offset + 2 + cipher_len
        c_curr = offset + 2
        while c_curr + 2 <= min(len(data), c_end):
            c_val = struct.unpack("!H", data[c_curr : c_curr + 2])[0]
            raw_ciphers.append(c_val)
            c_curr += 2

        offset += 2 + cipher_len

        # Compression Methods
        if offset >= len(data):
            return None, client_ver_name, cipher_count, [], raw_ciphers, [], [], [], None, None
        comp_len = data[offset]
        offset += 1 + comp_len

        # Extensions
        if offset + 2 > len(data):
            return None, client_ver_name, cipher_count, [], raw_ciphers, [], [], [], None, None
        ext_total_len = struct.unpack("!H", data[offset : offset + 2])[0]
        offset += 2

        sni: Optional[str] = None
        alpn_list: List[str] = []
        ext_list: List[int] = []
        curves_list: List[int] = []
        points_list: List[int] = []
        ext_end = min(len(data), offset + ext_total_len)

        while offset + 4 <= ext_end:
            ext_type, ext_len = struct.unpack("!HH", data[offset : offset + 4])
            offset += 4
            ext_list.append(ext_type)

            if offset + ext_len > ext_end:
                break

            ext_data = data[offset : offset + ext_len]
            offset += ext_len

            # Extension 0: Server Name Indication (SNI)
            if ext_type == 0 and len(ext_data) >= 5:
                name_type = ext_data[2]
                if name_type == 0:
                    name_len = struct.unpack("!H", ext_data[3:5])[0]
                    if len(ext_data) >= 5 + name_len:
                        sni = ext_data[5 : 5 + name_len].decode("ascii", errors="ignore")

            # Extension 10: Supported Groups (Elliptic Curves)
            elif ext_type == 10 and len(ext_data) >= 2:
                curves_len = struct.unpack("!H", ext_data[:2])[0]
                crv_curr = 2
                while crv_curr + 2 <= min(len(ext_data), 2 + curves_len):
                    crv_val = struct.unpack("!H", ext_data[crv_curr : crv_curr + 2])[0]
                    curves_list.append(crv_val)
                    crv_curr += 2

            # Extension 11: EC Point Formats
            elif ext_type == 11 and len(ext_data) >= 1:
                ec_len = ext_data[0]
                for p_idx in range(1, min(len(ext_data), 1 + ec_len)):
                    points_list.append(ext_data[p_idx])

            # Extension 16: ALPN
            elif ext_type == 16 and len(ext_data) >= 2:
                alpn_len = struct.unpack("!H", ext_data[:2])[0]
                curr = 2
                while curr < len(ext_data):
                    p_len = ext_data[curr]
                    curr += 1
                    if curr + p_len <= len(ext_data):
                        proto = ext_data[curr : curr + p_len].decode("ascii", errors="ignore")
                        alpn_list.append(proto)
                    curr += p_len

        # Compute JA3 string: SSLVersion,Cipher,Extensions,EllipticCurves,EllipticCurvePointFormats (excluding GREASE)
        ja3_ciphers = [c for c in raw_ciphers if c not in GREASE_SET]
        ja3_exts = [e for e in ext_list if e not in GREASE_SET]
        ja3_curves = [cr for cr in curves_list if cr not in GREASE_SET]

        ja3_str = (
            f"{client_ver},"
            f"{'-'.join(map(str, ja3_ciphers))},"
            f"{'-'.join(map(str, ja3_exts))},"
            f"{'-'.join(map(str, ja3_curves))},"
            f"{'-'.join(map(str, points_list))}"
        )
        ja3_hash = hashlib.md5(ja3_str.encode("ascii")).hexdigest()

        return (
            sni,
            client_ver_name,
            cipher_count,
            alpn_list,
            raw_ciphers,
            ext_list,
            curves_list,
            points_list,
            ja3_str,
            ja3_hash,
        )

