import requests
import config


def lookup_ip(ip_address):
    """
    Look up an IP address on VirusTotal.
    Returns how many security vendors flagged it as malicious.
    """
    headers = {
        "x-apikey": config.VIRUSTOTAL_API_KEY
    }

    try:
        response = requests.get(
            f"{config.VIRUSTOTAL_BASE_URL}/ip_addresses/{ip_address}",
            headers=headers,
            timeout=10
        )

        if response.status_code == 200:
            data = response.json().get("data", {})
            stats = data.get("attributes", {}).get("last_analysis_stats", {})
            return {
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0),
                "total_vendors": sum(stats.values()),
                "reputation": data.get("attributes", {}).get("reputation", 0)
            }
        elif response.status_code == 404:
            return {"error": "IP not found in VirusTotal database"}
        elif response.status_code == 429:
            return {"error": "Rate limit reached"}
        else:
            return {"error": f"Status code {response.status_code}"}

    except Exception as e:
        return {"error": str(e)}


def lookup_domain(domain):
    """
    Look up a domain on VirusTotal.
    Returns vendor detection results.
    """
    headers = {
        "x-apikey": config.VIRUSTOTAL_API_KEY
    }

    try:
        response = requests.get(
            f"{config.VIRUSTOTAL_BASE_URL}/domains/{domain}",
            headers=headers,
            timeout=10
        )

        if response.status_code == 200:
            data = response.json().get("data", {})
            stats = data.get("attributes", {}).get("last_analysis_stats", {})
            categories = data.get("attributes", {}).get("categories", {})
            return {
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0),
                "total_vendors": sum(stats.values()),
                "categories": list(categories.values())[:3],
                "reputation": data.get("attributes", {}).get("reputation", 0)
            }
        elif response.status_code == 404:
            return {"error": "Domain not found in VirusTotal database"}
        elif response.status_code == 429:
            return {"error": "Rate limit reached"}
        else:
            return {"error": f"Status code {response.status_code}"}

    except Exception as e:
        return {"error": str(e)}


def lookup_hash(file_hash):
    """
    Look up a file hash (MD5, SHA1, or SHA256) on VirusTotal.
    This is used in the search/lookup page.
    Returns how many antivirus engines detected it as malicious.
    """
    headers = {
        "x-apikey": config.VIRUSTOTAL_API_KEY
    }

    try:
        response = requests.get(
            f"{config.VIRUSTOTAL_BASE_URL}/files/{file_hash}",
            headers=headers,
            timeout=10
        )

        if response.status_code == 200:
            data = response.json().get("data", {})
            attrs = data.get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            return {
                "name": attrs.get("meaningful_name", "Unknown"),
                "type": attrs.get("type_description", "Unknown"),
                "size": attrs.get("size", 0),
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0),
                "total_vendors": sum(stats.values()),
                "threat_names": list(set(
                    v.get("result", "")
                    for v in attrs.get("last_analysis_results", {}).values()
                    if v.get("category") == "malicious" and v.get("result")
                ))[:5]
            }
        elif response.status_code == 404:
            return {"error": "Hash not found — file may be clean or unknown"}
        elif response.status_code == 429:
            return {"error": "Rate limit reached — try again in a minute"}
        else:
            return {"error": f"Status code {response.status_code}"}

    except Exception as e:
        return {"error": str(e)}
