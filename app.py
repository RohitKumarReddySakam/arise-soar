"""
ARISE SOAR - Security Orchestration, Automation & Response Platform
Author: Rohit Kumar Reddy Sakam
GitHub: https://github.com/RohitKumarReddySakam
Version: 2.0.0
"""

from flask import Flask, render_template, request, jsonify, Response
from flask_sqlalchemy import SQLAlchemy
from flask_socketio import SocketIO, emit
from datetime import datetime
import json
import os
import uuid
import threading
import time
import logging
from config import Config

# ─────────────────────────────────────────────
# App Initialization
# ─────────────────────────────────────────────
app = Flask(__name__)
app.config.from_object(Config)

db = SQLAlchemy(app)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Register template filters
from core.filters import register_filters
register_filters(app)

# ─────────────────────────────────────────────
# Lazy imports (avoid circular)
# ─────────────────────────────────────────────
def get_components():
    from core.alert_ingestion import AlertIngestion
    from core.playbook_engine import PlaybookEngine
    from core.case_management import CaseManager
    from core.ml_prioritizer import MLPrioritizer
    from core.integrations import IntegrationHub
    return AlertIngestion(), PlaybookEngine(), CaseManager(), MLPrioritizer(), IntegrationHub()

alert_ingestion = None
playbook_engine = None
case_manager = None
ml_prioritizer = None
integration_hub = None

# ─────────────────────────────────────────────
# Database Models
# ─────────────────────────────────────────────
class Alert(db.Model):
    __tablename__ = "alerts"
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    type = db.Column(db.String(100), nullable=False)
    severity = db.Column(db.String(20), nullable=False)
    source = db.Column(db.String(100))
    description = db.Column(db.Text)
    indicators = db.Column(db.Text, default="{}")
    status = db.Column(db.String(50), default="NEW")
    ml_priority = db.Column(db.Float, default=0.0)
    ml_label = db.Column(db.String(20), default="LOW")
    playbook_triggered = db.Column(db.String(100))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def to_dict(self):
        return {
            "id": self.id,
            "type": self.type,
            "severity": self.severity,
            "source": self.source,
            "description": self.description,
            "indicators": json.loads(self.indicators or "{}"),
            "status": self.status,
            "ml_priority": self.ml_priority,
            "ml_label": self.ml_label,
            "playbook_triggered": self.playbook_triggered,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class Case(db.Model):
    __tablename__ = "cases"
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    severity = db.Column(db.String(20))
    status = db.Column(db.String(50), default="OPEN")
    assigned_to = db.Column(db.String(100), default="SOC Team")
    alert_ids = db.Column(db.Text, default="[]")
    timeline = db.Column(db.Text, default="[]")
    mitre_tactics = db.Column(db.Text, default="[]")
    tags = db.Column(db.Text, default="[]")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    closed_at = db.Column(db.DateTime)

    def to_dict(self):
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "status": self.status,
            "assigned_to": self.assigned_to,
            "alert_ids": json.loads(self.alert_ids or "[]"),
            "timeline": json.loads(self.timeline or "[]"),
            "mitre_tactics": json.loads(self.mitre_tactics or "[]"),
            "tags": json.loads(self.tags or "[]"),
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class PlaybookExecution(db.Model):
    __tablename__ = "playbook_executions"
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    playbook_name = db.Column(db.String(100))
    alert_id = db.Column(db.String(36))
    status = db.Column(db.String(50), default="RUNNING")
    steps_completed = db.Column(db.Integer, default=0)
    steps_total = db.Column(db.Integer, default=0)
    results = db.Column(db.Text, default="[]")
    execution_time_ms = db.Column(db.Float)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            "id": self.id,
            "playbook_name": self.playbook_name,
            "alert_id": self.alert_id,
            "status": self.status,
            "steps_completed": self.steps_completed,
            "steps_total": self.steps_total,
            "results": json.loads(self.results or "[]"),
            "execution_time_ms": self.execution_time_ms,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


# ─────────────────────────────────────────────
# Routes — Dashboard
# ─────────────────────────────────────────────
@app.route("/")
def dashboard():
    total_alerts = Alert.query.count()
    open_cases = Case.query.filter_by(status="OPEN").count()
    critical_alerts = Alert.query.filter_by(severity="CRITICAL").count()
    resolved_today = Case.query.filter(
        Case.status == "CLOSED",
        Case.updated_at >= datetime.utcnow().replace(hour=0, minute=0, second=0),
    ).count()
    recent_alerts = Alert.query.order_by(Alert.created_at.desc()).limit(5).all()
    recent_cases = Case.query.order_by(Case.created_at.desc()).limit(5).all()
    mttr = _calculate_mttr()
    return render_template(
        "index.html",
        total_alerts=total_alerts,
        open_cases=open_cases,
        critical_alerts=critical_alerts,
        resolved_today=resolved_today,
        recent_alerts=recent_alerts,
        recent_cases=recent_cases,
        mttr=mttr,
    )


def _calculate_mttr():
    closed = Case.query.filter(Case.status == "CLOSED", Case.closed_at.isnot(None)).all()
    if not closed:
        return "N/A"
    deltas = [(c.closed_at - c.created_at).total_seconds() / 60 for c in closed if c.closed_at]
    if not deltas:
        return "N/A"
    avg = sum(deltas) / len(deltas)
    return f"{avg:.1f} min"


# ─────────────────────────────────────────────
# Routes — Alerts
# ─────────────────────────────────────────────
@app.route("/alerts")
def alerts_page():
    alerts = Alert.query.order_by(Alert.created_at.desc()).all()
    return render_template("alerts.html", alerts=alerts)


@app.route("/api/alerts", methods=["GET"])
def get_alerts():
    alerts = Alert.query.order_by(Alert.created_at.desc()).limit(100).all()
    return jsonify({"alerts": [a.to_dict() for a in alerts], "total": len(alerts)})


@app.route("/api/alerts", methods=["POST"])
def create_alert():
    global alert_ingestion, ml_prioritizer, playbook_engine
    data = request.get_json()
    if not data:
        return jsonify({"error": "No data provided"}), 400

    # ML scoring
    priority_score, priority_label = 0.5, "MEDIUM"
    if ml_prioritizer:
        priority_score, priority_label = ml_prioritizer.score(data)

    alert = Alert(
        type=data.get("type", "unknown"),
        severity=data.get("severity", "MEDIUM").upper(),
        source=data.get("source", "manual"),
        description=data.get("description", ""),
        indicators=json.dumps(data.get("indicators", {})),
        ml_priority=priority_score,
        ml_label=priority_label,
        status="NEW",
    )
    db.session.add(alert)
    db.session.commit()

    # Auto-trigger playbook
    pb_name = None
    if playbook_engine:
        pb_name = playbook_engine.auto_trigger(alert.to_dict(), db, PlaybookExecution)
        if pb_name:
            alert.playbook_triggered = pb_name
            alert.status = "IN_PROGRESS"
            db.session.commit()

    result = alert.to_dict()
    result["playbook_triggered"] = pb_name

    # Broadcast via WebSocket
    socketio.emit("new_alert", result)
    logger.info(f"Alert created: {alert.id} | Severity: {alert.severity} | ML: {priority_label}")
    return jsonify(result), 201


@app.route("/api/alerts/<alert_id>", methods=["PATCH"])
def update_alert(alert_id):
    alert = Alert.query.get_or_404(alert_id)
    data = request.get_json()
    for field in ["status", "description"]:
        if field in data:
            setattr(alert, field, data[field])
    alert.updated_at = datetime.utcnow()
    db.session.commit()
    socketio.emit("alert_updated", alert.to_dict())
    return jsonify(alert.to_dict())


# ─────────────────────────────────────────────
# Routes — Cases
# ─────────────────────────────────────────────
@app.route("/cases")
def cases_page():
    cases = Case.query.order_by(Case.created_at.desc()).all()
    return render_template("cases.html", cases=cases)


@app.route("/api/cases", methods=["GET"])
def get_cases():
    cases = Case.query.order_by(Case.created_at.desc()).all()
    return jsonify({"cases": [c.to_dict() for c in cases]})


@app.route("/api/cases", methods=["POST"])
def create_case():
    data = request.get_json()
    case = Case(
        title=data.get("title", "Untitled Case"),
        description=data.get("description", ""),
        severity=data.get("severity", "MEDIUM"),
        assigned_to=data.get("assigned_to", "SOC Team"),
        alert_ids=json.dumps(data.get("alert_ids", [])),
        mitre_tactics=json.dumps(data.get("mitre_tactics", [])),
        tags=json.dumps(data.get("tags", [])),
    )
    entry = {"timestamp": datetime.utcnow().isoformat(), "action": "Case created", "actor": "System"}
    case.timeline = json.dumps([entry])
    db.session.add(case)
    db.session.commit()
    socketio.emit("new_case", case.to_dict())
    return jsonify(case.to_dict()), 201


@app.route("/api/cases/<case_id>", methods=["PATCH"])
def update_case(case_id):
    case = Case.query.get_or_404(case_id)
    data = request.get_json()
    for field in ["status", "severity", "assigned_to", "description"]:
        if field in data:
            setattr(case, field, data[field])
    if data.get("status") == "CLOSED":
        case.closed_at = datetime.utcnow()
    # Append timeline entry
    if data.get("timeline_entry"):
        tl = json.loads(case.timeline or "[]")
        tl.append({"timestamp": datetime.utcnow().isoformat(), "action": data["timeline_entry"], "actor": "Analyst"})
        case.timeline = json.dumps(tl)
    case.updated_at = datetime.utcnow()
    db.session.commit()
    socketio.emit("case_updated", case.to_dict())
    return jsonify(case.to_dict())


# ─────────────────────────────────────────────
# Routes — Playbooks
# ─────────────────────────────────────────────
@app.route("/playbooks")
def playbooks_page():
    executions = PlaybookExecution.query.order_by(PlaybookExecution.created_at.desc()).limit(20).all()
    return render_template("playbooks.html", executions=executions)


@app.route("/api/playbooks", methods=["GET"])
def list_playbooks():
    pb_dir = os.path.join(os.path.dirname(__file__), "playbooks")
    playbooks = []
    for f in os.listdir(pb_dir):
        if f.endswith(".yaml"):
            playbooks.append(f.replace(".yaml", ""))
    return jsonify({"playbooks": playbooks})


@app.route("/api/playbooks/execute", methods=["POST"])
def execute_playbook():
    global playbook_engine
    data = request.get_json()
    playbook_name = data.get("playbook_name")
    alert_id = data.get("alert_id")

    if not playbook_engine:
        return jsonify({"error": "Playbook engine not initialized"}), 500

    execution = playbook_engine.execute(playbook_name, alert_id, db, PlaybookExecution)
    return jsonify(execution)


@app.route("/api/playbooks/executions", methods=["GET"])
def get_executions():
    execs = PlaybookExecution.query.order_by(PlaybookExecution.created_at.desc()).limit(50).all()
    return jsonify({"executions": [e.to_dict() for e in execs]})


# ─────────────────────────────────────────────
# Routes — Metrics / Analytics
# ─────────────────────────────────────────────
@app.route("/api/metrics", methods=["GET"])
def get_metrics():
    from sqlalchemy import func
    severity_dist = db.session.query(Alert.severity, func.count(Alert.id)).group_by(Alert.severity).all()
    type_dist = db.session.query(Alert.type, func.count(Alert.id)).group_by(Alert.type).all()
    status_dist = db.session.query(Case.status, func.count(Case.id)).group_by(Case.status).all()
    return jsonify({
        "severity_distribution": {k: v for k, v in severity_dist},
        "type_distribution": {k: v for k, v in type_dist},
        "case_status_distribution": {k: v for k, v in status_dist},
        "total_alerts": Alert.query.count(),
        "total_cases": Case.query.count(),
        "open_cases": Case.query.filter_by(status="OPEN").count(),
        "critical_alerts": Alert.query.filter_by(severity="CRITICAL").count(),
        "mttr": _calculate_mttr(),
        "automation_rate": _automation_rate(),
    })


def _automation_rate():
    total = Alert.query.count()
    auto = Alert.query.filter(Alert.playbook_triggered.isnot(None)).count()
    if total == 0:
        return 0
    return round((auto / total) * 100, 1)


# ─────────────────────────────────────────────
# Routes — Threat Intel Enrichment
# ─────────────────────────────────────────────
@app.route("/api/enrich", methods=["POST"])
def enrich_ioc():
    global integration_hub
    data = request.get_json()
    ioc = data.get("ioc")
    ioc_type = data.get("type", "ip")
    if not ioc:
        return jsonify({"error": "No IOC provided"}), 400
    if integration_hub:
        result = integration_hub.enrich(ioc, ioc_type)
    else:
        result = {"ioc": ioc, "type": ioc_type, "status": "enrichment_unavailable"}
    return jsonify(result)


# ─────────────────────────────────────────────
# Routes — Simulation (for demo purposes)
# ─────────────────────────────────────────────
@app.route("/api/simulate", methods=["POST"])
def simulate_attack():
    """Simulate different attack scenarios for demo purposes"""
    data = request.get_json()
    scenario = data.get("scenario", "phishing")
    
    scenarios = {
        "phishing": {
            "type": "phishing",
            "severity": "HIGH",
            "source": "email_gateway",
            "description": "Suspicious phishing email detected targeting multiple employees",
            "indicators": {
                "sender": "ceo-impersonator@evil-domain.tk",
                "subject": "URGENT: Verify your credentials immediately",
                "urls": ["http://company-login.evil-domain.tk/auth"],
                "recipients": 45,
                "attachment": "Invoice_Q4.pdf.exe"
            }
        },
        "ransomware": {
            "type": "ransomware",
            "severity": "CRITICAL",
            "source": "edr_agent",
            "description": "Ransomware activity detected - file encryption in progress",
            "indicators": {
                "host": "WORKSTATION-042",
                "process": "svchost.exe",
                "files_encrypted": 1247,
                "c2_ip": "185.220.101.47",
                "ransom_note": "YOUR_FILES_ARE_ENCRYPTED.txt"
            }
        },
        "brute_force": {
            "type": "brute_force",
            "severity": "HIGH",
            "source": "azure_ad",
            "description": "Brute force attack on VPN login portal",
            "indicators": {
                "target_user": "admin@company.com",
                "attacker_ip": "203.0.113.42",
                "attempts": 3847,
                "timespan": "15 minutes",
                "origin_country": "RU"
            }
        },
        "data_exfil": {
            "type": "data_exfiltration",
            "severity": "CRITICAL",
            "source": "dlp_system",
            "description": "Large data transfer to external IP detected",
            "indicators": {
                "source_host": "DB-SERVER-01",
                "destination_ip": "45.33.32.156",
                "data_transferred": "4.7 GB",
                "protocol": "HTTPS",
                "files": ["customer_data.zip", "financial_records.tar.gz"]
            }
        },
        "lateral_movement": {
            "type": "lateral_movement",
            "severity": "CRITICAL",
            "source": "siem",
            "description": "Suspicious lateral movement using stolen credentials",
            "indicators": {
                "source_ip": "10.0.1.55",
                "compromised_account": "svc_backup",
                "targets": ["DC01", "FILE-SERVER-02", "SQL-DB-01"],
                "technique": "Pass-the-Hash (T1550.002)"
            }
        },
    }

    alert_data = scenarios.get(scenario, scenarios["phishing"])
    
    # Use internal alert creation
    with app.test_request_context(json=alert_data):
        resp = create_alert()
    
    return jsonify({"message": f"Simulated {scenario} attack", "scenario": scenario}), 201


# ─────────────────────────────────────────────
# Health Check
# ─────────────────────────────────────────────
@app.route("/health")
def health():
    return jsonify({"status": "healthy", "timestamp": datetime.utcnow().isoformat(), "version": "2.0.0"})


# ─────────────────────────────────────────────
# WebSocket Events
# ─────────────────────────────────────────────
@socketio.on("connect")
def handle_connect():
    logger.info("Client connected via WebSocket")


@socketio.on("disconnect")
def handle_disconnect():
    logger.info("Client disconnected")


# ─────────────────────────────────────────────
# Background Alert Simulator (demo mode)
# ─────────────────────────────────────────────
def background_simulator():
    """Periodically emit mock alerts in demo mode"""
    import random
    scenarios = ["phishing", "brute_force", "ransomware", "data_exfil", "lateral_movement"]
    while True:
        time.sleep(30)
        try:
            if os.environ.get("DEMO_MODE", "true").lower() == "true":
                with app.app_context():
                    scenario = random.choice(scenarios)
                    scenarios_map = {
                        "phishing": {"type": "phishing", "severity": "HIGH", "source": "email_gateway", "description": f"Phishing attempt from spoofed domain"},
                        "brute_force": {"type": "brute_force", "severity": "MEDIUM", "source": "firewall", "description": "SSH brute force from external IP"},
                        "ransomware": {"type": "ransomware", "severity": "CRITICAL", "source": "edr_agent", "description": "Ransomware signature detected on endpoint"},
                        "data_exfil": {"type": "data_exfiltration", "severity": "HIGH", "source": "dlp", "description": "Unusual outbound data transfer"},
                        "lateral_movement": {"type": "lateral_movement", "severity": "CRITICAL", "source": "siem", "description": "Credential abuse across internal hosts"},
                    }
                    alert_data = scenarios_map[scenario]
                    alert_data["indicators"] = {}
                    
                    from core.ml_prioritizer import MLPrioritizer
                    ml = MLPrioritizer()
                    score, label = ml.score(alert_data)
                    
                    alert = Alert(
                        type=alert_data["type"],
                        severity=alert_data["severity"],
                        source=alert_data["source"],
                        description=alert_data["description"],
                        indicators="{}",
                        ml_priority=score,
                        ml_label=label,
                    )
                    db.session.add(alert)
                    db.session.commit()
                    socketio.emit("new_alert", alert.to_dict())
        except Exception as e:
            logger.error(f"Background simulator error: {e}")


# ─────────────────────────────────────────────
# Application Entry Point
# ─────────────────────────────────────────────
def create_app():
    global alert_ingestion, playbook_engine, case_manager, ml_prioritizer, integration_hub
    with app.app_context():
        db.create_all()
        # Seed demo data if empty
        if Alert.query.count() == 0:
            _seed_demo_data()

    alert_ingestion, playbook_engine, case_manager, ml_prioritizer, integration_hub = get_components()
    
    # Start background thread
    t = threading.Thread(target=background_simulator, daemon=True)
    t.start()
    return app


def _seed_demo_data():
    """Seed initial demo data"""
    import random
    alert_types = [
        ("phishing", "HIGH", "email_gateway"),
        ("malware", "CRITICAL", "edr_agent"),
        ("brute_force", "MEDIUM", "firewall"),
        ("data_exfiltration", "CRITICAL", "dlp_system"),
        ("lateral_movement", "HIGH", "siem"),
        ("privilege_escalation", "HIGH", "edr_agent"),
        ("ransomware", "CRITICAL", "edr_agent"),
        ("sql_injection", "HIGH", "waf"),
    ]
    for i in range(20):
        atype, severity, source = random.choice(alert_types)
        alert = Alert(
            type=atype,
            severity=severity,
            source=source,
            description=f"Demo: {atype.replace('_', ' ').title()} alert #{i+1}",
            indicators="{}",
            ml_priority=random.uniform(0.3, 0.99),
            ml_label=random.choice(["LOW", "MEDIUM", "HIGH", "CRITICAL"]),
            status=random.choice(["NEW", "IN_PROGRESS", "RESOLVED"]),
        )
        db.session.add(alert)

    for i in range(5):
        case = Case(
            title=f"IR-2025-{1000+i}: Security Incident",
            description="Active security investigation",
            severity=random.choice(["MEDIUM", "HIGH", "CRITICAL"]),
            status=random.choice(["OPEN", "IN_PROGRESS", "CLOSED"]),
            assigned_to="SOC Team",
        )
        entry = {"timestamp": datetime.utcnow().isoformat(), "action": "Case created", "actor": "System"}
        case.timeline = json.dumps([entry])
        db.session.add(case)

    db.session.commit()
    logger.info("Demo data seeded successfully")


if __name__ == "__main__":
    create_app()
    port = int(os.environ.get("PORT", 5000))
    socketio.run(app, host="0.0.0.0", port=port, debug=False)
