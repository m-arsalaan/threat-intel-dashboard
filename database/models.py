# This file defines what our database tables look like
# Think of each table like a spreadsheet with specific columns

CREATE_IOCS_TABLE = """
CREATE TABLE IF NOT EXISTS iocs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    indicator TEXT NOT NULL,
    type TEXT NOT NULL,
    threat_type TEXT,
    country TEXT,
    asn TEXT,
    abuse_score INTEGER DEFAULT 0,
    pulse_count INTEGER DEFAULT 1,
    source TEXT,
    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    is_correlated BOOLEAN DEFAULT 0
);
"""

# indicator = the actual IP or domain e.g. "192.168.1.1"
# type = "ip" or "domain" or "hash"
# threat_type = "malware", "scanning", "phishing" etc
# country = where the IP is from
# asn = the internet provider e.g. "AS15169 Google LLC"
# abuse_score = 0-100 from AbuseIPDB, higher = more dangerous
# pulse_count = how many threat feeds reported this IOC
# source = which feed it came from e.g. "AlienVault OTX"
# is_correlated = True if seen in multiple sources
