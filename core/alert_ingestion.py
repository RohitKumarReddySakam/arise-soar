"""
Alert Ingestion Engine
Normalizes and deduplicates alerts from multiple sources
"""

import json
import hashlib
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

SEVERITY_MAP = {
    "low": "LOW", "1": "LOW",
    "medium": "MEDIUM", "2": "MEDIUM", "warning": "MEDIUM",
    "high": "HIGH", "3": "HIGH", "error": "HIGH",
    "critical": "CRITICAL", "4": "CRITICAL", "emergency": "CRITICAL",
    "info": "LOW", "informational": "LOW",
}


class AlertIngestion:
    def __init__(self):
        self.seen_hashes = set()

    def normalize(self, raw: dict) -> dict:
        """Normalize alert from any source format"""
        normalized = {
            "type": self._extract_type(raw),
            "severity": self._extract_severity(raw),
            "source": raw.get("source", raw.get("origin", raw.get("device", "unknown"))),
            "description": raw.get("description", raw.get("message", raw.get("summary", ""))),
            "indicators": self._extract_indicators(raw),
            "timestamp": raw.get("timestamp", datetime.utcnow().isoformat()),
        }
        return normalized

    def _extract_type(self, raw: dict) -> str:
        for key in ["type", "alert_type", "category", "event_type", "rule_name"]:
            if key in raw:
                return str(raw[key]).lower().replace(" ", "_")
        return "unknown"

    def _extract_severity(self, raw: dict) -> str:
        for key in ["severity", "priority", "level", "risk_level"]:
            if key in raw:
                val = str(raw[key]).lower()
                return SEVERITY_MAP.get(val, "MEDIUM")
        return "MEDIUM"

    def _extract_indicators(self, raw: dict) -> dict:
        indicator_fields = ["indicators", "iocs", "artifacts", "evidence"]
        for field in indicator_fields:
            if field in raw and isinstance(raw[field], dict):
                return raw[field]
        # Build from common fields
        iocs = {}
        for field in ["ip", "src_ip", "dest_ip", "url", "domain", "hash", "user", "host"]:
            if field in raw:
                iocs[field] = raw[field]
        return iocs

    def is_duplicate(self, normalized: dict) -> bool:
        """Check for duplicate alerts using content hash"""
        content = f"{normalized['type']}:{normalized['source']}:{normalized.get('description', '')}"
        h = hashlib.md5(content.encode()).hexdigest()
        if h in self.seen_hashes:
            return True
        self.seen_hashes.add(h)
        # Keep set from growing too large
        if len(self.seen_hashes) > 10000:
            self.seen_hashes = set(list(self.seen_hashes)[-5000:])
        return False

    def from_syslog(self, message: str) -> dict:
        """Parse basic syslog message into alert format"""
        return {
            "type": "syslog_event",
            "severity": "LOW",
            "source": "syslog",
            "description": message,
            "indicators": {},
        }

    def from_webhook(self, payload: dict) -> dict:
        """Parse generic webhook payload"""
        return self.normalize(payload)
