import requests
import time
import config

from database.db import get_all_iocs, save_ioc
from utils.logger import logger


def enrich_ip_with_abuseipdb(ip_address):
    """
    Look up a single IP address on AbuseIPDB.
    """

    headers = {
        "Key": config.ABUSEIPDB_API_KEY,
        "Accept": "application/json"
    }

    params = {
        "ipAddress": ip_address,
        "maxAgeInDays": 90,
        "verbose": True
    }

    try:

        response = requests.get(
            f"{config.ABUSEIPDB_BASE_URL}/check",
            headers=headers,
            params=params,
            timeout=10
        )

        if response.status_code == 200:

            data = response.json().get("data", {})

            return {
                "abuse_score": data.get("abuseConfidenceScore", 0),
                "country": data.get("countryCode", "Unknown"),
                "isp": data.get("isp", "Unknown"),
                "usage_type": data.get("usageType", "Unknown"),
                "total_reports": data.get("totalReports", 0),
                "domain": data.get("domain", "")
            }

        elif response.status_code == 429:

            logger.info("Rate limit hit — waiting 60 seconds")
            time.sleep(60)
            return None

        else:

            logger.info(
                f"Error for {ip_address}: status {response.status_code}"
            )

            return None

    except requests.exceptions.Timeout:

        logger.info(f"Timeout for {ip_address}")
        return None

    except Exception as e:

        logger.info(f"Error: {e}")
        return None


def get_geolocation(ip_address):
    """
    Get geolocation using ip-api.com
    """

    try:

        response = requests.get(
            f"{config.GEOIP_BASE_URL}/{ip_address}",
            timeout=10
        )

        if response.status_code == 200:

            data = response.json()

            if data.get("status") == "success":

                return {
                    "country": data.get("country", "Unknown"),
                    "country_code": data.get("countryCode", ""),
                    "city": data.get("city", "Unknown"),
                    "region": data.get("regionName", ""),
                    "asn": data.get("as", "Unknown"),
                    "isp": data.get("isp", "Unknown")
                }

    except Exception as e:

        logger.info(f"GeoIP error for {ip_address}: {e}")

    return None


def enrich_all_ips():
    """
    Enrich all IP IOCs with AbuseIPDB + geolocation data.
    """

    logger.info("Starting IP enrichment...")

    all_iocs = get_all_iocs(limit=500)

    # Filter only IP IOCs
    ip_iocs = [
        ioc for ioc in all_iocs
        if ioc['type'] == 'ip'
    ]

    logger.info(f"Found {len(ip_iocs)} IP IOCs to enrich")

    enriched = 0
    skipped = 0

    for ioc in ip_iocs:

        ip = ioc['indicator']

        # Skip private/local IPs
        if ip.startswith((
            "192.168.",
            "10.",
            "172.16.",
            "127.",
            "1.2.3."
        )):
            skipped += 1
            continue

        # Geolocation
        geo = get_geolocation(ip)

        # AbuseIPDB lookup
        abuse_data = enrich_ip_with_abuseipdb(ip)

        if abuse_data:

            country = (
                geo['country']
                if geo
                else abuse_data.get('country', 'Unknown')
            )

            asn = (
                geo['asn']
                if geo
                else abuse_data.get('isp', 'Unknown')
            )

            # Update database
            save_ioc(
                indicator=ip,
                ioc_type="ip",
                threat_type=ioc['threat_type'],
                country=country,
                asn=asn,
                abuse_score=abuse_data['abuse_score'],
                source=ioc['source']
            )

            enriched += 1

            logger.info(
                f"{ip} | Score: {abuse_data['abuse_score']}% "
                f"| Country: {country}"
            )

        # Respect API limits
        time.sleep(1.5)

    logger.info(
        f"Enrichment complete — {enriched} enriched, {skipped} skipped"
    )

    return enriched
