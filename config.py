import os
from dotenv import load_dotenv

# Load the .env file so all API keys become available
load_dotenv()

# API Keys — loaded from .env file, never hardcoded
OTX_API_KEY = os.getenv("OTX_API_KEY")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")

# API Base URLs
OTX_BASE_URL = "https://otx.alienvault.com/api/v1"
ABUSEIPDB_BASE_URL = "https://api.abuseipdb.com/api/v2"
VIRUSTOTAL_BASE_URL = "https://www.virustotal.com/api/v3"
GEOIP_BASE_URL = "http://ip-api.com/json"

# Database
DATABASE_PATH = "database/threat_intel.db"

# Scheduler — how often to auto-refresh IOC feed (in minutes)
REFRESH_INTERVAL_MINUTES = 60

# How many IOCs to pull from OTX per refresh
OTX_LIMIT = 50
def validate_config():
    """Check all required API keys are set before app starts"""
    missing = []
    if not OTX_API_KEY:
        missing.append("OTX_API_KEY")
    if not ABUSEIPDB_API_KEY:
        missing.append("ABUSEIPDB_API_KEY")
    if not VIRUSTOTAL_API_KEY:
        missing.append("VIRUSTOTAL_API_KEY")
    if missing:
        raise ValueError(
            f"Missing required API keys in .env: {', '.join(missing)}\n"
            f"Copy .env.example to .env and fill in your keys."
        )
