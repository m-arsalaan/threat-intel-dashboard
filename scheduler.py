from apscheduler.schedulers.background import BackgroundScheduler
from collectors.otx_collector import fetch_otx_pulses
from collectors.abuseipdb import enrich_all_ips
from correlator.ioc_correlator import run_correlation
from database.db import init_db
import config


def refresh_all():
    """
    Full refresh cycle:
    1. Pull fresh IOCs from OTX
    2. Enrich IPs with AbuseIPDB scores
    3. Run correlation engine
    """
    print("[SCHEDULER] Starting scheduled refresh...")
    count = fetch_otx_pulses()
    print(f"[SCHEDULER] Fetched {count} IOCs")
    run_correlation()
    print("[SCHEDULER] Refresh complete")


def start_scheduler():
    """Start the background scheduler"""
    scheduler = BackgroundScheduler()

    # Run full refresh every hour
    scheduler.add_job(
        refresh_all,
        'interval',
        minutes=config.REFRESH_INTERVAL_MINUTES,
        id='ioc_refresh'
    )

    scheduler.start()
    print(f"[SCHEDULER] Started — refreshing every "
          f"{config.REFRESH_INTERVAL_MINUTES} minutes")
    return scheduler
