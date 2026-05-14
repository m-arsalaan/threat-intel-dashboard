import sqlite3
import config
from database.models import CREATE_IOCS_TABLE


def get_connection():
    """Create and return a database connection"""
    conn = sqlite3.connect(config.DATABASE_PATH)
    # This makes rows behave like dictionaries
    # so you can do row['indicator'] instead of row[0]
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Create database tables if they don't exist yet"""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(CREATE_IOCS_TABLE)
    conn.commit()
    conn.close()
    print("[DB] Database initialised successfully")


def save_ioc(indicator, ioc_type, threat_type=None, country=None,
             asn=None, abuse_score=0, source="AlienVault OTX"):
    """
    Save a single IOC to the database.
    If the same indicator already exists, update it instead of duplicating.
    """
    conn = get_connection()
    cursor = conn.cursor()

    # Check if this IOC already exists
    cursor.execute("SELECT id, pulse_count FROM iocs WHERE indicator = ?",
                   (indicator,))
    existing = cursor.fetchone()

    if existing:
        # Already exists — update last_seen and increment pulse_count
        cursor.execute("""
            UPDATE iocs
            SET last_seen = CURRENT_TIMESTAMP,
                pulse_count = pulse_count + 1,
                abuse_score = ?,
                country = ?,
                asn = ?
            WHERE indicator = ?
        """, (abuse_score, country, asn, indicator))
    else:
        # New IOC — insert it
        cursor.execute("""
            INSERT INTO iocs
            (indicator, type, threat_type, country, asn, abuse_score, source)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (indicator, ioc_type, threat_type, country, asn,
              abuse_score, source))

    conn.commit()
    conn.close()


def get_all_iocs(limit=200):
    """Fetch all IOCs ordered by most dangerous first"""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT * FROM iocs
        ORDER BY abuse_score DESC, pulse_count DESC
        LIMIT ?
    """, (limit,))
    rows = cursor.fetchall()
    conn.close()
    # Convert to list of regular dicts for easy use in templates
    return [dict(row) for row in rows]


def get_ioc_stats():
    """Get summary numbers for the dashboard cards"""
    conn = get_connection()
    cursor = conn.cursor()

    stats = {}

    # Total IOC count
    cursor.execute("SELECT COUNT(*) FROM iocs")
    stats['total'] = cursor.fetchone()[0]

    # Count by type
    cursor.execute("""
        SELECT type, COUNT(*) as count
        FROM iocs GROUP BY type
    """)
    type_counts = cursor.fetchall()
    stats['by_type'] = {row['type']: row['count'] for row in type_counts}

    # Count by threat category
    cursor.execute("""
        SELECT threat_type, COUNT(*) as count
        FROM iocs
        WHERE threat_type IS NOT NULL
        GROUP BY threat_type
        ORDER BY count DESC
        LIMIT 5
    """)
    stats['by_threat'] = [dict(row) for row in cursor.fetchall()]

    # High confidence IOCs (abuse score > 50)
    cursor.execute("SELECT COUNT(*) FROM iocs WHERE abuse_score > 50")
    stats['high_confidence'] = cursor.fetchone()[0]

    # Correlated IOCs
    cursor.execute("SELECT COUNT(*) FROM iocs WHERE is_correlated = 1")
    stats['correlated'] = cursor.fetchone()[0]

    conn.close()
    return stats


def search_ioc(query):
    """Search for a specific indicator"""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT * FROM iocs
        WHERE indicator LIKE ?
    """, (f"%{query}%",))
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]


def mark_correlated(indicator):
    """Mark an IOC as seen in multiple sources"""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        UPDATE iocs SET is_correlated = 1
        WHERE indicator = ?
    """, (indicator,))
    conn.commit()
    conn.close()
