import logging
import os
import time

import requests
from apscheduler.schedulers.background import BackgroundScheduler

logger = logging.getLogger("alphaguard.scheduler")
logging.basicConfig(level=logging.INFO)

# Set to a backend endpoint that runs a scan cycle (none exists in main.py yet).
SCAN_TRIGGER_URL = os.getenv("ALPHAGUARD_SCAN_TRIGGER_URL", "")
SCAN_TRIGGER_TOKEN = os.getenv("ALPHAGUARD_SCAN_TRIGGER_TOKEN", "")


def run_daily_scans():
    """Runs the automated scan cycle for all registered merchant catalogs."""
    logger.info("Triggering automated 24/7 threat detection scan...")
    if not SCAN_TRIGGER_URL:
        logger.warning("ALPHAGUARD_SCAN_TRIGGER_URL is not set; no scan was run.")
        return
    try:
        headers = {"Authorization": f"Bearer {SCAN_TRIGGER_TOKEN}"} if SCAN_TRIGGER_TOKEN else {}
        response = requests.post(SCAN_TRIGGER_URL, headers=headers, timeout=(5, 120))
        response.raise_for_status()
        logger.info("Scan cycle completed successfully.")
    except Exception:
        logger.exception("Error during background scan")


def start_background_scheduler() -> BackgroundScheduler:
    scheduler = BackgroundScheduler()
    scheduler.add_job(
        run_daily_scans,
        "interval",
        hours=24,
        max_instances=1,
        coalesce=True,
    )
    scheduler.start()
    logger.info("Background cron worker active. Running every 24 hours.")
    return scheduler


if __name__ == "__main__":
    scheduler = start_background_scheduler()
    try:
        while True:
            time.sleep(2)
    except (KeyboardInterrupt, SystemExit):
        scheduler.shutdown()
