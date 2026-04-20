"""Tests for Playbook Engine"""
import pytest
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.playbook_engine import PlaybookEngine, PLAYBOOK_TRIGGER_MAP


def test_playbooks_loaded():
    engine = PlaybookEngine()
    assert len(engine._playbook_cache) > 0


def test_phishing_playbook_exists():
    engine = PlaybookEngine()
    assert "phishing_response" in engine._playbook_cache


def test_ransomware_playbook_exists():
    engine = PlaybookEngine()
    assert "ransomware_response" in engine._playbook_cache


def test_trigger_map_coverage():
    assert "phishing" in PLAYBOOK_TRIGGER_MAP
    assert "ransomware" in PLAYBOOK_TRIGGER_MAP
    assert "brute_force" in PLAYBOOK_TRIGGER_MAP
    assert "data_exfiltration" in PLAYBOOK_TRIGGER_MAP


def test_list_playbooks():
    engine = PlaybookEngine()
    playbooks = engine.list_playbooks()
    assert isinstance(playbooks, list)
    assert len(playbooks) > 0
    for pb in playbooks:
        assert "name" in pb
        assert "steps_count" in pb


def test_playbook_has_steps():
    engine = PlaybookEngine()
    pb = engine._playbook_cache.get("phishing_response", {})
    assert "steps" in pb
    assert len(pb["steps"]) > 0


def test_simulate_action():
    engine = PlaybookEngine()
    result = engine._simulate_action("block_ip", {})
    assert "IP" in result or "ip" in result.lower() or "firewall" in result.lower()
