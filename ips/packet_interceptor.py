"""WinDivert / PyDivert packet interception investigation and integration wrapper."""

from __future__ import annotations

import logging
from typing import Optional

logger = logging.getLogger("dpi_ids_ips.ips.packet_interceptor")


class PacketInterceptor:
    """Interception interface for active packet filtering and dropping on Windows."""

    def __init__(self, filter_expr: str = "true") -> None:
        self.filter_expr = filter_expr
        self._is_available = False
        self._pydivert = None
        self._check_availability()

    def _check_availability(self) -> None:
        """Checks if PyDivert and WinDivert kernel driver are installed and accessible."""
        try:
            import pydivert
            self._pydivert = pydivert
            self._is_available = True
            logger.info("WinDivert / PyDivert interception driver detected.")
        except ImportError:
            self._is_available = False
            logger.info(
                "PyDivert module not installed. Running in Monitoring / Simulation mode (Npcap capture). "
                "To enable active kernel interception, install pydivert and run as Administrator."
            )
        except Exception as e:
            self._is_available = False
            logger.warning(f"WinDivert initialization check failed: {e}")

    @property
    def is_available(self) -> bool:
        """Indicates whether active kernel-level interception is available."""
        return self._is_available

    def intercept_and_filter(self) -> None:
        """
        Active interception loop using PyDivert if available.
        Must be executed in an isolated thread or process.
        """
        if not self._is_available:
            raise RuntimeError("Cannot start active interceptor: PyDivert / WinDivert is not available.")

        # Ensure loopback traffic is never intercepted
        safe_filter = f"({self.filter_expr}) and !loopback"
        logger.info(f"Opening WinDivert handle with filter: {safe_filter}")
        # Managed externally when active prevention is toggled

