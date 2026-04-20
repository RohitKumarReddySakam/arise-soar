"""
Playbook Execution Engine
Parses YAML playbooks and executes response actions automatically
"""

import os
import yaml
import json
import time
import uuid
import logging
from datetime import datetime
import threading

logger = logging.getLogger(__name__)

PLAYBOOK_TRIGGER_MAP = {
    "phishing": "phishing_response",
    "ransomware": "ransomware_response",
    "brute_force": "brute_force_response",
    "data_exfiltration": "data_breach_response",
    "malware": "malware_containment",
    "lateral_movement": "malware_containment",
    "privilege_escalation": "malware_containment",
    "sql_injection": "brute_force_response",
}


class PlaybookEngine:
    def __init__(self):
        self.playbook_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "playbooks")
        self._playbook_cache = {}
        self._load_playbooks()

    def _load_playbooks(self):
        if not os.path.exists(self.playbook_dir):
            os.makedirs(self.playbook_dir)
        for filename in os.listdir(self.playbook_dir):
            if filename.endswith(".yaml"):
                name = filename.replace(".yaml", "")
                path = os.path.join(self.playbook_dir, filename)
                try:
                    with open(path) as f:
                        self._playbook_cache[name] = yaml.safe_load(f)
                    logger.info(f"Loaded playbook: {name}")
                except Exception as e:
                    logger.error(f"Failed to load playbook {name}: {e}")

    def auto_trigger(self, alert: dict, db, PlaybookExecution) -> str | None:
        """Automatically trigger the appropriate playbook for an alert"""
        alert_type = alert.get("type", "").lower()
        pb_name = PLAYBOOK_TRIGGER_MAP.get(alert_type)
        if not pb_name or pb_name not in self._playbook_cache:
            return None
        # Execute in background thread
        t = threading.Thread(
            target=self.execute,
            args=(pb_name, alert.get("id"), db, PlaybookExecution),
            daemon=True
        )
        t.start()
        return pb_name

    def execute(self, playbook_name: str, alert_id: str, db, PlaybookExecution) -> dict:
        """Execute a playbook and record results"""
        playbook = self._playbook_cache.get(playbook_name)
        if not playbook:
            return {"error": f"Playbook '{playbook_name}' not found"}

        steps = playbook.get("steps", [])
        execution_id = str(uuid.uuid4())
        results = []
        start = time.time()

        # Create execution record
        try:
            from app import app
            with app.app_context():
                exec_record = PlaybookExecution(
                    id=execution_id,
                    playbook_name=playbook_name,
                    alert_id=alert_id,
                    steps_total=len(steps),
                    status="RUNNING",
                )
                db.session.add(exec_record)
                db.session.commit()

                for i, step in enumerate(steps):
                    result = self._execute_step(step)
                    results.append(result)
                    exec_record.steps_completed = i + 1
                    exec_record.results = json.dumps(results)
                    db.session.commit()
                    time.sleep(0.3)  # Simulate execution

                exec_record.status = "COMPLETED"
                exec_record.execution_time_ms = (time.time() - start) * 1000
                exec_record.results = json.dumps(results)
                db.session.commit()

                logger.info(f"Playbook '{playbook_name}' completed in {exec_record.execution_time_ms:.0f}ms")
                return exec_record.to_dict()
        except Exception as e:
            logger.error(f"Playbook execution failed: {e}")
            return {"error": str(e), "playbook_name": playbook_name}

    def _execute_step(self, step: dict) -> dict:
        """Simulate execution of a single playbook step"""
        action = step.get("action", "unknown")
        result = {
            "action": action,
            "description": step.get("description", ""),
            "status": "success",
            "timestamp": datetime.utcnow().isoformat(),
            "output": self._simulate_action(action, step),
        }
        return result

    def _simulate_action(self, action: str, step: dict) -> str:
        action_responses = {
            "block_ip": "IP address added to firewall deny list",
            "block_sender": "Email sender quarantined at gateway",
            "isolate_host": "Host removed from network segment",
            "force_password_reset": "Password reset initiated for affected accounts",
            "notify_team": "Slack notification sent to #soc-alerts channel",
            "create_ticket": "Jira ticket IR-{} created".format(int(time.time()) % 10000),
            "collect_forensics": "Memory dump and event logs collected",
            "scan_network": "Network scan initiated for lateral movement",
            "enrich_ioc": "IOC enriched via VirusTotal and AbuseIPDB",
            "quarantine_email": "Phishing email quarantined across mailboxes",
            "enable_mfa": "MFA enforcement enabled for affected accounts",
            "revoke_tokens": "Active session tokens revoked",
            "preserve_evidence": "Digital evidence preserved and hashed",
            "notify_legal": "Legal team notified via secure channel",
            "terminate_process": "Malicious process terminated on endpoint",
        }
        return action_responses.get(action, f"Action '{action}' executed successfully")

    def list_playbooks(self) -> list:
        return [
            {
                "name": name,
                "description": pb.get("description", ""),
                "trigger": pb.get("trigger", ""),
                "steps_count": len(pb.get("steps", [])),
                "severity": pb.get("severity", "HIGH"),
                "avg_time": pb.get("avg_execution_time", "30s"),
            }
            for name, pb in self._playbook_cache.items()
        ]
