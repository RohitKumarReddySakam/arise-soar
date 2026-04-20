"""Tests for ML Prioritization Engine"""
import pytest
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.ml_prioritizer import MLPrioritizer


def test_score_critical_ransomware():
    ml = MLPrioritizer()
    alert = {"type": "ransomware", "severity": "CRITICAL", "source": "edr_agent", "description": "Ransomware encrypt files"}
    score, label = ml.score(alert)
    assert score > 0.8
    assert label in ("CRITICAL", "HIGH")


def test_score_low_severity():
    ml = MLPrioritizer()
    alert = {"type": "port_scan", "severity": "LOW", "source": "firewall", "description": "Port scan"}
    score, label = ml.score(alert)
    assert score < 0.6


def test_score_returns_tuple():
    ml = MLPrioritizer()
    result = ml.score({"type": "phishing", "severity": "HIGH", "source": "email_gateway"})
    assert isinstance(result, tuple)
    assert len(result) == 2
    assert isinstance(result[0], float)
    assert isinstance(result[1], str)


def test_score_range():
    ml = MLPrioritizer()
    score, _ = ml.score({"type": "unknown", "severity": "MEDIUM", "source": "unknown"})
    assert 0.0 <= score <= 1.0


def test_label_consistency():
    ml = MLPrioritizer()
    valid_labels = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
    for alert_type in ["ransomware", "phishing", "brute_force", "port_scan"]:
        _, label = ml.score({"type": alert_type, "severity": "MEDIUM", "source": "test"})
        assert label in valid_labels


def test_batch_score():
    ml = MLPrioritizer()
    alerts = [
        {"id": "1", "type": "ransomware", "severity": "CRITICAL", "source": "edr"},
        {"id": "2", "type": "port_scan", "severity": "LOW", "source": "firewall"},
    ]
    results = ml.batch_score(alerts)
    assert len(results) == 2
    assert results[0]["id"] == "1"
