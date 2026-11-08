"""HTTP Protocol Inspector for parsing plaintext requests and responses."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, Optional, Tuple

HTTP_METHODS = {"GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "CONNECT", "TRACE"}


@dataclass
class HTTPMetadata:
    """Extracted HTTP message fields."""
    is_request: bool
    method: Optional[str] = None
    uri: Optional[str] = None
    version: Optional[str] = None
    status_code: Optional[int] = None
    reason_phrase: Optional[str] = None
    headers: Dict[str, str] = field(default_factory=dict)
    host: Optional[str] = None
    user_agent: Optional[str] = None
    content_type: Optional[str] = None
    content_length: Optional[int] = None
    body_preview: str = ""


class HTTPInspector:
    """Inspects and dissects HTTP/1.0 and HTTP/1.1 traffic."""

    @classmethod
    def is_http(cls, payload: bytes) -> bool:
        """Determines if the payload begins with a valid HTTP method or HTTP status line."""
        if len(payload) < 4:
            return False

        # Check request method
        first_token = payload.split(b" ", 1)[0].decode("ascii", errors="ignore").upper()
        if first_token in HTTP_METHODS:
            return True

        # Check response line: "HTTP/1."
        if payload.startswith(b"HTTP/1.") or payload.startswith(b"HTTP/2"):
            return True

        return False

    @classmethod
    def inspect(cls, payload: bytes) -> Optional[HTTPMetadata]:
        """
        Parses HTTP request or response lines and headers.

        Args:
            payload: Application layer bytes or reassembled TCP stream.

        Returns:
            HTTPMetadata dataclass or None if not valid HTTP.
        """
        if not cls.is_http(payload):
            return None

        # Split headers from body
        header_part = payload
        body_part = b""
        if b"\r\n\r\n" in payload:
            header_part, body_part = payload.split(b"\r\n\r\n", 1)
        elif b"\n\n" in payload:
            header_part, body_part = payload.split(b"\n\n", 1)

        try:
            header_text = header_part.decode("iso-8859-1")
        except Exception:
            header_text = header_part.decode("utf-8", errors="ignore")

        lines = header_text.splitlines()
        if not lines:
            return None

        first_line = lines[0].strip()
        parts = first_line.split(" ", 2)

        is_request = False
        method = None
        uri = None
        version = None
        status_code = None
        reason_phrase = None

        if parts[0].upper() in HTTP_METHODS:
            is_request = True
            method = parts[0].upper()
            uri = parts[1] if len(parts) > 1 else "/"
            version = parts[2] if len(parts) > 2 else "HTTP/1.1"
        elif parts[0].startswith("HTTP/"):
            is_request = False
            version = parts[0]
            if len(parts) > 1 and parts[1].isdigit():
                status_code = int(parts[1])
            if len(parts) > 2:
                reason_phrase = parts[2]
        else:
            return None

        headers: Dict[str, str] = {}
        for line in lines[1:]:
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip().lower()] = v.strip()

        host = headers.get("host")
        user_agent = headers.get("user-agent")
        content_type = headers.get("content-type")
        content_length = None
        if "content-length" in headers and headers["content-length"].isdigit():
            content_length = int(headers["content-length"])

        # Preview first 256 bytes of body
        body_preview = ""
        if body_part:
            body_preview = body_part[:256].decode("utf-8", errors="replace")

        return HTTPMetadata(
            is_request=is_request,
            method=method,
            uri=uri,
            version=version,
            status_code=status_code,
            reason_phrase=reason_phrase,
            headers=headers,
            host=host,
            user_agent=user_agent,
            content_type=content_type,
            content_length=content_length,
            body_preview=body_preview,
        )

