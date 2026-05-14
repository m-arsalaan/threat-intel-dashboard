from database.db import get_all_iocs, mark_correlated, get_connection


def calculate_confidence_score(ioc):
    """
    Calculate a confidence score for how dangerous an IOC is.
    Score is based on multiple factors — this is real threat scoring logic.

    Scoring breakdown:
    - Seen in multiple threat pulses: up to 40 points
    - High AbuseIPDB score: up to 40 points
    - IOC type weight: up to 20 points
    """
    score = 0

    # Factor 1 — how many threat feeds reported this IOC
    pulse_count = ioc.get('pulse_count', 1)
    if pulse_count >= 5:
        score += 40
    elif pulse_count >= 3:
        score += 25
    elif pulse_count >= 2:
        score += 15
    else:
        score += 0

    # Factor 2 — AbuseIPDB abuse score
    abuse_score = ioc.get('abuse_score', 0)
    if abuse_score >= 80:
        score += 40
    elif abuse_score >= 50:
        score += 25
    elif abuse_score >= 20:
        score += 10
    else:
        score += 0

    # Factor 3 — threat type weight
    threat_type = ioc.get('threat_type', '')
    threat_weights = {
        'malware': 20,
        'botnet': 20,
        'exploitation': 18,
        'phishing': 15,
        'scanning': 10,
        'spam': 5,
        'suspicious': 3
    }
    score += threat_weights.get(threat_type, 0)

    return min(score, 100)  # cap at 100


def get_severity_label(confidence_score):
    """Convert confidence score to human-readable severity"""
    if confidence_score >= 70:
        return "CRITICAL"
    elif confidence_score >= 50:
        return "HIGH"
    elif confidence_score >= 30:
        return "MEDIUM"
    else:
        return "LOW"


def run_correlation():
    """
    Full correlation run:
    1. Find IOCs seen in multiple feeds
    2. Calculate confidence scores
    3. Mark high-confidence IOCs as correlated
    4. Log results by severity
    """
    from utils.logger import logger
    logger.info("Starting IOC correlation engine...")

    all_iocs = get_all_iocs(limit=1000)

    correlated_count = 0
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}

    conn = get_connection()
    cursor = conn.cursor()

    for ioc in all_iocs:
        confidence = calculate_confidence_score(ioc)
        severity = get_severity_label(confidence)
        severity_counts[severity] += 1

        # Mark as correlated if confidence is HIGH or CRITICAL
        if confidence >= 50:
            mark_correlated(ioc['indicator'])
            correlated_count += 1

            # Update confidence score in database
            cursor.execute("""
                UPDATE iocs SET is_correlated = 1
                WHERE indicator = ?
            """, (ioc['indicator'],))

    conn.commit()
    conn.close()

    logger.info(f"Correlation complete — {correlated_count} high-confidence IOCs")
    logger.info(f"Severity breakdown: {severity_counts}")
    return correlated_count
