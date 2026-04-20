"""
Case Management System
Manages security incident cases with full lifecycle tracking
"""

import json
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

MITRE_TACTICS = {
    "phishing": ["TA0001 - Initial Access", "T1566 - Phishing"],
    "ransomware": ["TA0040 - Impact", "T1486 - Data Encrypted for Impact"],
    "lateral_movement": ["TA0008 - Lateral Movement", "T1550 - Use Alternate Auth Material"],
    "data_exfiltration": ["TA0010 - Exfiltration", "T1041 - Exfiltration Over C2 Channel"],
    "brute_force": ["TA0006 - Credential Access", "T1110 - Brute Force"],
    "privilege_escalation": ["TA0004 - Privilege Escalation", "T1068 - Exploitation for Priv Esc"],
    "malware": ["TA0002 - Execution", "T1204 - User Execution"],
}


class CaseManager:
    def create_from_alert(self, alert: dict, db, Case) -> dict:
        """Automatically create a case from a critical/high alert"""
        alert_type = alert.get("type", "unknown")
        severity = alert.get("severity", "MEDIUM")
        
        if severity not in ("CRITICAL", "HIGH"):
            return None

        mitre = MITRE_TACTICS.get(alert_type, [])
        timeline_entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "action": f"Auto-created from {severity} {alert_type} alert",
            "actor": "ARISE SOAR",
        }

        case = Case(
            title=f"IR-{int(datetime.utcnow().timestamp()) % 100000}: {alert_type.replace('_', ' ').title()} Incident",
            description=alert.get("description", ""),
            severity=severity,
            alert_ids=json.dumps([alert.get("id", "")]),
            mitre_tactics=json.dumps(mitre),
            timeline=json.dumps([timeline_entry]),
            tags=json.dumps([alert_type, severity.lower(), "auto-created"]),
        )
        db.session.add(case)
        db.session.commit()
        logger.info(f"Case auto-created: {case.id} for alert {alert.get('id')}")
        return case.to_dict()

    def add_timeline_event(self, case_id: str, action: str, actor: str, db, Case) -> dict:
        case = Case.query.get(case_id)
        if not case:
            return {"error": "Case not found"}
        tl = json.loads(case.timeline or "[]")
        tl.append({
            "timestamp": datetime.utcnow().isoformat(),
            "action": action,
            "actor": actor,
        })
        case.timeline = json.dumps(tl)
        case.updated_at = datetime.utcnow()
        db.session.commit()
        return case.to_dict()

    def get_open_cases_summary(self, db, Case) -> dict:
        open_cases = Case.query.filter_by(status="OPEN").all()
        critical = [c for c in open_cases if c.severity == "CRITICAL"]
        return {
            "total_open": len(open_cases),
            "critical": len(critical),
            "cases": [c.to_dict() for c in open_cases[:10]],
        }
