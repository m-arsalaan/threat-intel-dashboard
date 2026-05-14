from database.db import get_all_iocs
from utils.logger import logger


# ISO 27001 Annex A control definitions
# Maps threat types to relevant controls
ISO_CONTROLS = {
    "malware": {
        "control_id": "A.12.2",
        "control_name": "Protection from malware",
        "domain": "Operations Security",
        "description": (
            "Controls against malware shall be implemented, "
            "supported by appropriate user awareness."
        ),
        "recommendation": (
            "Ensure endpoint protection is deployed and updated. "
            "Investigate all malware IOCs for potential infections."
        )
    },
    "botnet": {
        "control_id": "A.13.1",
        "control_name": "Network security management",
        "domain": "Communications Security",
        "description": (
            "Networks shall be managed and controlled to protect "
            "information in systems and applications."
        ),
        "recommendation": (
            "Block botnet C2 IPs at perimeter firewall. "
            "Review outbound traffic logs for connections to these indicators."
        )
    },
    "phishing": {
        "control_id": "A.7.2.2",
        "control_name": "Information security awareness and training",
        "domain": "Human Resource Security",
        "description": (
            "All employees shall receive appropriate awareness education "
            "and training relevant to their job function."
        ),
        "recommendation": (
            "Block phishing domains at DNS/proxy level. "
            "Issue user awareness alert about active phishing campaign."
        )
    },
    "exploitation": {
        "control_id": "A.12.6",
        "control_name": "Management of technical vulnerabilities",
        "domain": "Operations Security",
        "description": (
            "Information about technical vulnerabilities of systems shall "
            "be obtained in a timely fashion."
        ),
        "recommendation": (
            "Patch affected systems immediately. "
            "Review vulnerability management process for related CVEs."
        )
    },
    "scanning": {
        "control_id": "A.13.1",
        "control_name": "Network security management",
        "domain": "Communications Security",
        "description": (
            "Networks shall be managed and controlled to protect "
            "information in systems and applications."
        ),
        "recommendation": (
            "Block scanning IPs at perimeter. "
            "Review firewall rules and IDS/IPS signatures."
        )
    },
    "spam": {
        "control_id": "A.13.2",
        "control_name": "Information transfer",
        "domain": "Communications Security",
        "description": (
            "Formal transfer policies, procedures and controls shall "
            "be in place to protect information transfer."
        ),
        "recommendation": (
            "Block spam sources at email gateway. "
            "Review email filtering and anti-spam controls."
        )
    },
    "suspicious": {
        "control_id": "A.16.1",
        "control_name": "Management of information security incidents",
        "domain": "Incident Management",
        "description": (
            "A consistent and effective approach to the management of "
            "information security incidents shall be implemented."
        ),
        "recommendation": (
            "Investigate suspicious indicators further. "
            "Log and track as potential incident for review."
        )
    }
}

# Severity color mapping for the UI
SEVERITY_COLORS = {
    "CRITICAL": "danger",
    "HIGH": "warning",
    "MEDIUM": "info",
    "LOW": "secondary"
}


def get_compliance_report():
    """
    Generate a full ISO 27001 compliance report
    based on current IOCs in the database.

    Returns a list of control violations with
    IOC counts, severity, and recommendations.
    """
    logger.info("Generating ISO 27001 compliance report...")

    all_iocs = get_all_iocs(limit=1000)

    # Group IOCs by threat type
    threat_groups = {}
    for ioc in all_iocs:
        threat = ioc.get("threat_type") or "suspicious"
        if threat not in threat_groups:
            threat_groups[threat] = []
        threat_groups[threat].append(ioc)

    # Build compliance findings
    findings = []

    for threat_type, iocs in threat_groups.items():
        control = ISO_CONTROLS.get(threat_type, ISO_CONTROLS["suspicious"])

        # Calculate severity based on IOC count and abuse scores
        high_confidence = [
            i for i in iocs if i.get("abuse_score", 0) > 50
            or i.get("is_correlated", 0)
        ]

        total = len(iocs)
        if total >= 50 or len(high_confidence) >= 10:
            severity = "CRITICAL"
        elif total >= 20 or len(high_confidence) >= 5:
            severity = "HIGH"
        elif total >= 5:
            severity = "MEDIUM"
        else:
            severity = "LOW"

        findings.append({
            "control_id": control["control_id"],
            "control_name": control["control_name"],
            "domain": control["domain"],
            "description": control["description"],
            "recommendation": control["recommendation"],
            "threat_type": threat_type,
            "ioc_count": total,
            "high_confidence_count": len(high_confidence),
            "severity": severity,
            "severity_color": SEVERITY_COLORS[severity],
            "sample_iocs": iocs[:5]
        })

    # Sort by severity — CRITICAL first
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    findings.sort(key=lambda x: severity_order[x["severity"]])

    # Summary stats
    summary = {
        "total_violations": len(findings),
        "critical": sum(1 for f in findings if f["severity"] == "CRITICAL"),
        "high": sum(1 for f in findings if f["severity"] == "HIGH"),
        "medium": sum(1 for f in findings if f["severity"] == "MEDIUM"),
        "low": sum(1 for f in findings if f["severity"] == "LOW"),
        "total_iocs": len(all_iocs),
        "controls_violated": len(set(f["control_id"] for f in findings))
    }

    logger.info(
        f"Compliance report complete — "
        f"{summary['controls_violated']} controls violated, "
        f"{summary['critical']} CRITICAL findings"
    )

    return {"findings": findings, "summary": summary}
