import os
from datetime import timedelta


class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "arise-soar-dev-secret-2025-change-in-prod")
    SQLALCHEMY_DATABASE_URI = os.environ.get("DATABASE_URL", "sqlite:///arise_soar.db")
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ECHO = False

    # API Keys (set via environment variables)
    VIRUSTOTAL_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY", "")
    ABUSEIPDB_API_KEY = os.environ.get("ABUSEIPDB_API_KEY", "")
    SHODAN_API_KEY = os.environ.get("SHODAN_API_KEY", "")
    SLACK_WEBHOOK_URL = os.environ.get("SLACK_WEBHOOK_URL", "")

    # Demo mode (generates background alerts)
    DEMO_MODE = os.environ.get("DEMO_MODE", "true").lower() == "true"

    # ML Settings
    ML_MODEL_PATH = os.environ.get("ML_MODEL_PATH", "models/alert_prioritizer.pkl")
    ML_CONFIDENCE_THRESHOLD = float(os.environ.get("ML_CONFIDENCE_THRESHOLD", "0.7"))

    # Rate limiting
    RATELIMIT_DEFAULT = "200 per day;50 per hour"
