"""
Integration Hub
Connects ARISE SOAR to external threat intelligence & SIEM tools
"""

import os
import json
import logging
import requests
from datetime import datetime

logger = logging.getLogger(__name__)


class IntegrationHub:
    def __init__(self):
        self.vt_key = os.environ.get("VIRUSTOTAL_API_KEY", "")
        self.abuse_key = os.environ.get("ABUSEIPDB_API_KEY", "")
        self.slack_webhook = os.environ.get("SLACK_WEBHOOK_URL", "")
        self.timeout = 5

    def enrich(self, ioc: str, ioc_type: str) -> dict:
        """Enrich an IOC with threat intelligence"""
        result = {
            "ioc": ioc,
            "type": ioc_type,
            "timestamp": datetime.utcnow().isoformat(),
            "sources": [],
        }

        if ioc_type == "ip":
            if self.abuse_key:
                abuse_result = self._query_abuseipdb(ioc)
                result["sources"].append({"name": "AbuseIPDB", "data": abuse_result})
            if self.vt_key:
                vt_result = self._query_virustotal_ip(ioc)
                result["sources"].append({"name": "VirusTotal", "data": vt_result})

        elif ioc_type in ("url", "domain"):
            if self.vt_key:
                vt_result = self._query_virustotal_url(ioc)
                result["sources"].append({"name": "VirusTotal", "data": vt_result})

        elif ioc_type == "hash":
            if self.vt_key:
                vt_result = self._query_virustotal_hash(ioc)
                result["sources"].append({"name": "VirusTotal", "data": vt_result})

        # If no API keys, return mock enrichment
        if not result["sources"]:
            result["sources"].append({"name": "mock", "data": self._mock_enrich(ioc, ioc_type)})

        result["risk_score"] = self._calculate_risk_score(result["sources"])
        return result

    def _query_abuseipdb(self, ip: str) -> dict:
        try:
            r = requests.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers={"Key": self.abuse_key, "Accept": "application/json"},
                params={"ipAddress": ip, "maxAgeInDays": 90},
                timeout=self.timeout,
            )
            data = r.json().get("data", {})
            return {
                "abuse_confidence": data.get("abuseConfidenceScore", 0),
                "total_reports": data.get("totalReports", 0),
                "country": data.get("countryCode", "Unknown"),
                "isp": data.get("isp", "Unknown"),
                "is_tor": data.get("isTor", False),
            }
        except Exception as e:
            return {"error": str(e)}

    def _query_virustotal_ip(self, ip: str) -> dict:
        try:
            r = requests.get(
                f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
                headers={"x-apikey": self.vt_key},
                timeout=self.timeout,
            )
            attrs = r.json().get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            return {
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "country": attrs.get("country", "Unknown"),
            }
        except Exception as e:
            return {"error": str(e)}

    def _query_virustotal_url(self, url: str) -> dict:
        import base64
        try:
            url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
            r = requests.get(
                f"https://www.virustotal.com/api/v3/urls/{url_id}",
                headers={"x-apikey": self.vt_key},
                timeout=self.timeout,
            )
            attrs = r.json().get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            return {"malicious": stats.get("malicious", 0), "suspicious": stats.get("suspicious", 0)}
        except Exception as e:
            return {"error": str(e)}

    def _query_virustotal_hash(self, file_hash: str) -> dict:
        try:
            r = requests.get(
                f"https://www.virustotal.com/api/v3/files/{file_hash}",
                headers={"x-apikey": self.vt_key},
                timeout=self.timeout,
            )
            attrs = r.json().get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            return {
                "malicious": stats.get("malicious", 0),
                "name": attrs.get("meaningful_name", "Unknown"),
                "type": attrs.get("type_description", "Unknown"),
            }
        except Exception as e:
            return {"error": str(e)}

    def _mock_enrich(self, ioc: str, ioc_type: str) -> dict:
        import random
        return {
            "note": "No API keys configured — showing simulated enrichment",
            "risk_level": random.choice(["Low", "Medium", "High", "Critical"]),
            "first_seen": "2024-11-15",
            "tags": ["malware", "botnet"] if random.random() > 0.5 else ["clean"],
            "country": random.choice(["RU", "CN", "US", "KP", "IR"]),
        }

    def _calculate_risk_score(self, sources: list) -> int:
        score = 0
        for source in sources:
            data = source.get("data", {})
            if "abuse_confidence" in data:
                score = max(score, data["abuse_confidence"])
            if "malicious" in data:
                score = max(score, min(data["malicious"] * 5, 100))
        return score

    def send_slack_alert(self, title: str, message: str, severity: str = "HIGH") -> bool:
        if not self.slack_webhook:
            logger.info(f"Slack alert (no webhook configured): {title}")
            return False
        color_map = {"CRITICAL": "#FF0000", "HIGH": "#FF6600", "MEDIUM": "#FFCC00", "LOW": "#36A64F"}
        payload = {
            "attachments": [{
                "color": color_map.get(severity, "#36A64F"),
                "title": f"🚨 ARISE SOAR: {title}",
                "text": message,
                "footer": "ARISE SOAR Platform",
                "ts": int(datetime.utcnow().timestamp()),
            }]
        }
        try:
            r = requests.post(self.slack_webhook, json=payload, timeout=self.timeout)
            return r.status_code == 200
        except Exception as e:
            logger.error(f"Slack notification failed: {e}")
            return False
