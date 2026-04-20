"""
ML-Powered Alert Prioritization Engine
Uses Random Forest to score alerts by criticality
"""

import os
import pickle
import logging
import numpy as np
from datetime import datetime

logger = logging.getLogger(__name__)

# Feature encoding maps
TYPE_SCORES = {
    "ransomware": 0.98, "data_exfiltration": 0.95, "lateral_movement": 0.93,
    "privilege_escalation": 0.90, "malware": 0.88, "apt": 0.95,
    "brute_force": 0.65, "phishing": 0.70, "sql_injection": 0.72,
    "xss": 0.55, "dos": 0.60, "port_scan": 0.40, "unknown": 0.50,
}

SEVERITY_SCORES = {"CRITICAL": 1.0, "HIGH": 0.75, "MEDIUM": 0.50, "LOW": 0.25}

SOURCE_WEIGHTS = {
    "edr_agent": 0.95, "siem": 0.90, "dlp_system": 0.92, "firewall": 0.70,
    "email_gateway": 0.65, "waf": 0.68, "azure_ad": 0.75, "manual": 0.50, "unknown": 0.50,
}

LABEL_THRESHOLDS = [
    (0.85, "CRITICAL"),
    (0.70, "HIGH"),
    (0.50, "MEDIUM"),
    (0.0, "LOW"),
]


class MLPrioritizer:
    def __init__(self):
        self.model = None
        self._load_or_build_model()

    def _load_or_build_model(self):
        model_path = "models/alert_prioritizer.pkl"
        if os.path.exists(model_path):
            try:
                with open(model_path, "rb") as f:
                    self.model = pickle.load(f)
                logger.info("ML model loaded from disk")
                return
            except Exception as e:
                logger.warning(f"Could not load ML model: {e}")
        # Build lightweight heuristic model as fallback
        self.model = None
        logger.info("Using heuristic prioritizer")

    def _extract_features(self, alert: dict) -> list:
        alert_type = str(alert.get("type", "unknown")).lower()
        severity = str(alert.get("severity", "MEDIUM")).upper()
        source = str(alert.get("source", "unknown")).lower()
        description = str(alert.get("description", ""))
        indicators = alert.get("indicators", {})

        type_score = TYPE_SCORES.get(alert_type, 0.50)
        sev_score = SEVERITY_SCORES.get(severity, 0.50)
        src_weight = SOURCE_WEIGHTS.get(source, 0.50)
        
        # Keyword analysis
        critical_keywords = ["ransomware", "exfil", "breach", "critical", "encrypt", "lateral", "c2", "command"]
        keyword_score = sum(1 for kw in critical_keywords if kw in description.lower()) / len(critical_keywords)
        
        # Indicator richness
        ioc_count = len(indicators) / 10.0 if indicators else 0

        return [type_score, sev_score, src_weight, keyword_score, ioc_count]

    def score(self, alert: dict) -> tuple:
        """Return (score: float 0-1, label: str)"""
        features = self._extract_features(alert)
        
        if self.model:
            try:
                arr = np.array(features).reshape(1, -1)
                proba = self.model.predict_proba(arr)[0]
                score = float(proba[1]) if len(proba) > 1 else float(proba[0])
            except Exception:
                score = self._heuristic_score(features)
        else:
            score = self._heuristic_score(features)

        # Apply weights: type + severity are primary signals
        label = "LOW"
        for threshold, lbl in LABEL_THRESHOLDS:
            if score >= threshold:
                label = lbl
                break

        return round(score, 4), label

    def _heuristic_score(self, features: list) -> float:
        # Weighted combination: type(40%) + severity(35%) + source(15%) + keywords(7%) + iocs(3%)
        weights = [0.40, 0.35, 0.15, 0.07, 0.03]
        return sum(f * w for f, w in zip(features, weights))

    def batch_score(self, alerts: list) -> list:
        return [{"id": a.get("id"), "score": self.score(a)} for a in alerts]
