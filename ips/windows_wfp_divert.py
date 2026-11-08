"""Windows Filtering Platform (WFP) and WinDivert / PyDivert investigation and diagnostic subsystem."""

from __future__ import annotations

import ctypes
from dataclasses import dataclass
import logging
import os
import sys
from typing import Dict, Optional, Tuple

logger = logging.getLogger("dpi_ids_ips.ips.windows_wfp")


@dataclass
class WindowsFilteringStatus:
    """Diagnostic telemetry regarding available Windows kernel filtering capabilities."""
    os_name: str
    is_windows: bool
    is_administrator: bool
    wfp_dll_loaded: bool
    wfp_engine_accessible: bool
    wfp_error_code: Optional[int]
    pydivert_installed: bool
    windivert_driver_active: bool
    selected_enforcement_mechanism: str
    diagnostics_summary: str


class WindowsWFPInvestigator:
    """Investigates Windows Filtering Platform and WinDivert/PyDivert availability."""

    @staticmethod
    def is_admin() -> bool:
        """Determines if the current process possesses elevated Administrator rights."""
        if sys.platform != "win32":
            return False
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False

    @classmethod
    def investigate(cls) -> WindowsFilteringStatus:
        """Runs diagnostics on WFP, WinDivert, and gateway filtering capabilities."""
        is_win = sys.platform == "win32"
        is_admin = cls.is_admin()
        wfp_dll_loaded = False
        wfp_engine_accessible = False
        wfp_error_code = None
        pydivert_installed = False
        windivert_driver_active = False

        if is_win:
            # 1. Check fwpuclnt.dll (WFP user-mode API)
            try:
                fwpuclnt = ctypes.windll.LoadLibrary("fwpuclnt.dll")
                wfp_dll_loaded = True

                # Attempt FwpmEngineOpen0
                h_engine = ctypes.c_void_p()
                # FwpmEngineOpen0(serverName, authnService, authIdentity, session, phEngine)
                ret = fwpuclnt.FwpmEngineOpen0(None, 10, None, None, ctypes.byref(h_engine))
                if ret == 0:
                    wfp_engine_accessible = True
                    fwpuclnt.FwpmEngineClose0(h_engine)
                else:
                    wfp_error_code = ret
            except Exception as e:
                logger.debug(f"WFP DLL investigation error: {e}")

            # 2. Check PyDivert / WinDivert
            try:
                import pydivert
                pydivert_installed = True
                # Attempt opening a minimal handle if admin
                if is_admin:
                    try:
                        with pydivert.WinDivert("false") as w:
                            windivert_driver_active = True
                    except Exception as we:
                        logger.debug(f"WinDivert handle test: {we}")
            except ImportError:
                pydivert_installed = False
            except Exception:
                pydivert_installed = False

        # Determine best available enforcement mechanism
        if pydivert_installed and windivert_driver_active:
            mechanism = "WinDivert Kernel Callout Driver (WFP-Integrated)"
            summary = "Kernel-level WFP packet interception and reinjection active."
        elif wfp_engine_accessible and is_admin:
            mechanism = "Native Windows Filtering Platform (WFP Filter Rules)"
            summary = "WFP engine accessible. Dynamic kernel filtering rules enabled."
        else:
            mechanism = "Inline VPN Gateway Packet Filter & Forwarder"
            summary = (
                "Terminating WireGuard VPN gateway enforcement path selected. "
                "Packets are inspected, decided, and forwarded or dropped directly along the gateway routing path. "
                "WFP / WinDivert kernel callout available when running elevated as Administrator."
            )

        return WindowsFilteringStatus(
            os_name=sys.platform,
            is_windows=is_win,
            is_administrator=is_admin,
            wfp_dll_loaded=wfp_dll_loaded,
            wfp_engine_accessible=wfp_engine_accessible,
            wfp_error_code=wfp_error_code,
            pydivert_installed=pydivert_installed,
            windivert_driver_active=windivert_driver_active,
            selected_enforcement_mechanism=mechanism,
            diagnostics_summary=summary,
        )

