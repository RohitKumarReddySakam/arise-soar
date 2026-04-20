"""Tests for Alert Ingestion Engine"""
import pytest
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.alert_ingestion import AlertIngestion


def test_normalize_basic():
    ingestion = AlertIngestion()
    raw = {"type": "phishing", "severity": "HIGH", "source": "email_gateway", "description": "Test alert"}
    normalized = ingestion.normalize(raw)
    assert normalized["type"] == "phishing"
    assert normalized["severity"] == "HIGH"
    assert normalized["source"] == "email_gateway"


def test_normalize_severity_mapping():
    ingestion = AlertIngestion()
    raw = {"type": "test", "severity": "critical"}
    normalized = ingestion.normalize(raw)
    assert normalized["severity"] == "CRITICAL"


def test_normalize_unknown_severity():
    ingestion = AlertIngestion()
    raw = {"type": "test", "severity": "unknown_level"}
    normalized = ingestion.normalize(raw)
    assert normalized["severity"] == "MEDIUM"


def test_duplicate_detection():
    ingestion = AlertIngestion()
    alert = {"type": "phishing", "source": "email_gateway", "description": "Same alert"}
    n1 = ingestion.normalize(alert)
    assert not ingestion.is_duplicate(n1)
    assert ingestion.is_duplicate(n1)


def test_extract_indicators():
    ingestion = AlertIngestion()
    raw = {"type": "malware", "indicators": {"ip": "1.2.3.4", "hash": "abc123"}}
    normalized = ingestion.normalize(raw)
    assert "ip" in normalized["indicators"]


def test_from_syslog():
    ingestion = AlertIngestion()
    result = ingestion.from_syslog("Failed password for root from 192.168.1.100")
    assert result["type"] == "syslog_event"
    assert "192.168.1.100" in result["description"]
