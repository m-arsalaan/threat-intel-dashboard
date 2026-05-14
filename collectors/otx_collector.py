import requests
import config

from database.db import save_ioc
from utils.logger import logger


def fetch_otx_pulses():
    """
    Fetch latest threat pulses from AlienVault OTX.
    A 'pulse' is a threat report — it contains indicators (IOCs)
    like malicious IPs, domains, and file hashes.
    """

    logger.info("Starting IOC collection from AlienVault OTX...")

    headers = {
        "X-OTX-API-KEY": config.OTX_API_KEY
    }

    # This endpoint gives us the latest pulses from the community
    url = f"{config.OTX_BASE_URL}/pulses/subscribed"

    params = {
        "limit": 10,
        "page": 1
    }

    total_saved = 0

    try:
        response = requests.get(
            url,
            headers=headers,
            params=params,
            timeout=15
        )

        if response.status_code != 200:
            logger.info(f"Error: API returned status {response.status_code}")
            return 0

        data = response.json()
        pulses = data.get("results", [])

        logger.info(f"Found {len(pulses)} threat pulses")

        for pulse in pulses:

            pulse_name = pulse.get("name", "Unknown")
            indicators = pulse.get("indicators", [])

            logger.info(
                f"Processing pulse: '{pulse_name}' — {len(indicators)} indicators"
            )

            for indicator in indicators:

                ioc_value = indicator.get("indicator", "")
                ioc_type_raw = indicator.get("type", "")
                description = indicator.get("description", "")

                # Normalize IOC type
                if "IPv4" in ioc_type_raw or "IPv6" in ioc_type_raw:
                    ioc_type = "ip"

                elif (
                    "domain" in ioc_type_raw.lower()
                    or "hostname" in ioc_type_raw.lower()
                ):
                    ioc_type = "domain"

                elif (
                    "hash" in ioc_type_raw.lower()
                    or "filehash" in ioc_type_raw.lower()
                ):
                    ioc_type = "hash"

                else:
                    continue

                # Determine threat type
                threat_type = classify_threat(
                    pulse_name + " " + description
                )

                # Save IOC
                save_ioc(
                    indicator=ioc_value,
                    ioc_type=ioc_type,
                    threat_type=threat_type,
                    source="AlienVault OTX"
                )

                total_saved += 1

        logger.info(
            f"Collection complete — {total_saved} IOCs saved to database"
        )

        return total_saved

    except requests.exceptions.Timeout:
        logger.info("Error: Request timed out")
        return 0

    except requests.exceptions.ConnectionError:
        logger.info("Error: Could not connect to OTX API")
        return 0

    except Exception as e:
        logger.info(f"Unexpected error: {e}")
        return 0


def classify_threat(text):
    """
    Look at the pulse name and description and guess the threat category.
    """

    text = text.lower()

    if any(
        word in text
        for word in [
            "malware",
            "trojan",
            "rat",
            "backdoor",
            "ransomware"
        ]
    ):
        return "malware"

    elif any(
        word in text
        for word in [
            "phishing",
            "credential",
            "login",
            "fake"
        ]
    ):
        return "phishing"

    elif any(
        word in text
        for word in [
            "scan",
            "brute",
            "recon",
            "crawler"
        ]
    ):
        return "scanning"

    elif any(
        word in text
        for word in [
            "botnet",
            "c2",
            "command",
            "control"
        ]
    ):
        return "botnet"

    elif any(
        word in text
        for word in [
            "exploit",
            "vulnerability",
            "cve"
        ]
    ):
        return "exploitation"

    elif any(
        word in text
        for word in [
            "spam",
            "bulk"
        ]
    ):
        return "spam"

    else:
        return "suspicious"
