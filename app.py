from flask import Flask, render_template, request, jsonify
from database.db import init_db, get_all_iocs, get_ioc_stats, search_ioc
from collectors.otx_collector import fetch_otx_pulses
from collectors.abuseipdb import enrich_all_ips
from collectors.virustotal import lookup_ip, lookup_domain, lookup_hash
from utils.logger import logger
import re

app = Flask(__name__)


@app.route("/")
def dashboard():
    """Main dashboard page — shows stats and charts"""
    stats = get_ioc_stats()
    recent_iocs = get_all_iocs(limit=20)
    return render_template("dashboard.html", stats=stats, iocs=recent_iocs)


@app.route("/iocs")
def ioc_table():
    """Full IOC table page"""
    iocs = get_all_iocs(limit=200)
    return render_template("ioc_table.html", iocs=iocs)


@app.route("/lookup")
def lookup_page():
    """Search/lookup page"""
    return render_template("lookup.html")


@app.route("/api/lookup", methods=["POST"])
def api_lookup():
    """
    API endpoint for the lookup page.
    Accepts an indicator (IP, domain, hash) and returns
    combined results from our database + VirusTotal.
    """
    data = request.get_json()
    query = data.get("query", "").strip()

    if not query:
        return jsonify({"error": "No query provided"}), 400

    if len(query) < 3:
        return jsonify({"error": "Query too short — minimum 3 characters"}), 400

    if len(query) > 512:
        return jsonify({"error": "Query too long — maximum 512 characters"}), 400

    if re.search(r'[;\'"\\]', query):
        return jsonify({"error": "Invalid characters in query"}), 400

    logger.info(f"Lookup query received: {query}")

    # Search local database first
    local_results = search_ioc(query)

    # Determine type and query VirusTotal
    vt_result = None

    # Hash: 32 chars MD5, 40 chars SHA1, 64 chars SHA256
    if re.match(r'^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$', query):
        vt_result = lookup_hash(query)
        query_type = "hash"
    # IP address
    elif re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', query):
        vt_result = lookup_ip(query)
        query_type = "ip"
    # Domain
    else:
        vt_result = lookup_domain(query)
        query_type = "domain"

    logger.info(f"Lookup complete for {query} — type: {query_type}, "
                f"local results: {len(local_results)}, "
                f"VT error: {vt_result.get('error') if vt_result else 'none'}")

    return jsonify({
        "query": query,
        "type": query_type,
        "local_results": local_results,
        "virustotal": vt_result
    })


@app.route("/api/refresh", methods=["POST"])
def api_refresh():
    """Manually trigger IOC feed refresh"""
    try:
        logger.info("Manual feed refresh triggered")
        count = fetch_otx_pulses()
        from correlator.ioc_correlator import run_correlation
        run_correlation()
        logger.info(f"Manual refresh complete — {count} IOCs processed")
        return jsonify({
            "success": True,
            "message": f"Refreshed successfully — {count} IOCs processed"
        })
    except Exception as e:
        logger.error(f"Refresh failed: {e}")
        return jsonify({"success": False, "message": str(e)}), 500


@app.route("/api/stats")
def api_stats():
    """Return current stats as JSON — used by dashboard charts"""
    stats = get_ioc_stats()
    return jsonify(stats)


if __name__ == "__main__":
    from config import validate_config
    validate_config()
    init_db()
    from scheduler import start_scheduler
    start_scheduler()
    logger.info("Threat Intelligence Dashboard starting on http://0.0.0.0:5000")
    app.run(debug=False, host="0.0.0.0", port=5000)
