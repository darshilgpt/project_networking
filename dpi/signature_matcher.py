"""Rule-based Signature Matcher supporting exact, substring, case-insensitive, and regex."""

from __future__ import annotations

import json
import logging
import os
import re
from typing import Any, Dict, List, Optional

logger = logging.getLogger("dpi_ids_ips.dpi.signature_matcher")


class SignatureMatcher:
    """Matches protocol fields and raw payloads against configured DPI inspection rules."""

    def __init__(self, rules_path: Optional[str] = None) -> None:
        self.rules: List[Dict[str, Any]] = []
        self._compiled_regexes: Dict[int, re.Pattern] = {}

        if rules_path:
            self.load_rules(rules_path)
        else:
            default_path = os.path.join(os.path.dirname(__file__), "..", "rules", "dpi_rules.json")
            if os.path.exists(default_path):
                self.load_rules(default_path)

    def load_rules(self, filepath: str) -> int:
        """Loads and compiles rules from a JSON file."""
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                rules_data = json.load(f)
            self.rules = []
            self._compiled_regexes.clear()

            for r in rules_data:
                rule_id = r.get("id")
                match_type = r.get("match_type", "substring").lower()
                pattern = r.get("pattern", "")

                if match_type == "regex" and pattern:
                    try:
                        self._compiled_regexes[rule_id] = re.compile(pattern, re.IGNORECASE)
                    except re.error as re_err:
                        logger.error(f"Invalid regex in rule {rule_id}: {re_err}")
                        continue

                self.rules.append(r)

            logger.info(f"Loaded {len(self.rules)} DPI rules from '{filepath}'")
            return len(self.rules)
        except Exception as e:
            logger.error(f"Error loading DPI rules from {filepath}: {e}")
            return 0

    def match(
        self,
        protocol: str,
        fields: Dict[str, Any],
        raw_payload: bytes = b"",
    ) -> List[Dict[str, Any]]:
        """
        Evaluates active rules against the supplied protocol fields and payload.

        Args:
            protocol: Protocol string ("HTTP", "DNS", "TLS", etc.).
            fields: Dict of extracted protocol attributes (e.g. {"uri": "/admin", "sni": "..."}).
            raw_payload: Raw payload bytes for payload inspection.

        Returns:
            List of matched rule dictionaries.
        """
        matches: List[Dict[str, Any]] = []

        payload_text = None
        try:
            payload_text = raw_payload.decode("utf-8", errors="ignore")
        except Exception:
            payload_text = ""

        for rule in self.rules:
            rule_proto = rule.get("protocol", "ANY").upper()
            if rule_proto != "ANY" and rule_proto != protocol.upper():
                continue

            field_name = rule.get("field", "payload").lower()
            pattern = rule.get("pattern", "")
            match_type = rule.get("match_type", "substring").lower()

            target_val = ""
            if field_name == "payload":
                target_val = payload_text
            else:
                raw_val = fields.get(field_name)
                if raw_val is None:
                    continue
                target_val = str(raw_val)

            matched = False

            if match_type == "exact":
                matched = (target_val == pattern)
            elif match_type == "case_insensitive":
                matched = (target_val.lower() == pattern.lower())
            elif match_type == "substring":
                matched = (pattern.lower() in target_val.lower())
            elif match_type == "regex":
                rule_id = rule.get("id")
                c_re = self._compiled_regexes.get(rule_id)
                if c_re:
                    matched = bool(c_re.search(target_val))

            if matched:
                match_entry = dict(rule)
                match_entry["matched_field"] = field_name
                match_entry["matched_value"] = target_val[:128]
                matches.append(match_entry)

        return matches

