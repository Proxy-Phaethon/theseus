import requests

from datetime import datetime, timezone
from urllib.parse import quote

CRT_ENDPOINT = "https://crt.sh/"
WAYBACK_ENDPOINT = "https://web.archive.org/cdx/search/cdx"
URLSCAN_ENDPOINT = "https://urlscan.io/api/v1/search/"

TIMEOUT = 20
MAX_URLSCAN_RESULTS = 100
MAX_WAYBACK_RESULTS = 1000

FIELDS = (
    "previously_associated_ip_addresses",
    "previously_associated_nameservers",
    "historical_subdomains",
    "historical_certificates",
    "previous_registrant_organisations",
    "previous_hosting_providers",
    "previously_observed_email_infrastructure",
    "reported_malicious_ip_addresses",
    "reported_malicious_urls",
    "malware_and_phishing_references",
    "public_abuse_reports",
    "threat_intelligence_identifiers",
    "first_seen_date",
    "last_seen_date",
    "historical_organisation_and_infrastructure_associations",
)

def empty_data() -> dict:
    return {
        field: []
        for field in FIELDS
    }

def unique(values: list) -> list:
    result = []
    seen = set()

    for value in values:
        if value is None or value == "":
            continue

        if isinstance(value, dict):
            key = repr(sorted(value.items()))
        else:
            value = str(value).strip()

            if not value:
                continue

            key = value.lower()

        if key not in seen:
            seen.add(key)
            result.append(value)

    return sorted(
        result,
        key=lambda item: str(item).lower()
    )

def request_json(url: str, params: dict = None) -> dict:
    response = requests.get(
        url,
        params=params,
        headers={
            "User-Agent": "Theseus/1.0",
            "Accept": "application/json"
        },
        timeout=TIMEOUT
    )

    response.raise_for_status()
    return response.json()

def retrieve_certificates(domain: str) -> list:
    certificates = {}

    queries = [
        domain,
        f"%.{domain}"
    ]

    for query in queries:
        try:
            response = requests.get(
                CRT_ENDPOINT,
                params={
                    "q": query,
                    "output": "json"
                },
                headers={"User-Agent": "Theseus/1.0"},
                timeout=TIMEOUT
            )

            response.raise_for_status()

            records = response.json()

            if not isinstance(records, list):
                continue

            for record in records:
                certificate_id = record.get("id")

                if not certificate_id:
                    continue

                certificates[str(certificate_id)] = {
                    "id": certificate_id,
                    "issuer": record.get("issuer_name"),
                    "common_name": record.get("common_name"),
                    "hostnames": sorted(set(
                        name.strip().lower().rstrip(".")
                        for name in (
                            record.get("name_value") or ""
                        ).splitlines()
                        if name.strip()
                    )),
                    "not_before": record.get("not_before"),
                    "not_after": record.get("not_after"),
                    "entry_timestamp": record.get(
                        "entry_timestamp"
                    )
                }

        except (
            requests.RequestException,
            ValueError,
            TypeError
        ):
            continue

    return list(certificates.values())

def retrieve_wayback_records(domain: str) -> list:
    try:
        response = requests.get(
            WAYBACK_ENDPOINT,
            params={
                "url": f"{domain}/*",
                "output": "json",
                "fl": "timestamp,original,statuscode,mimetype",
                "filter": "statuscode:200",
                "collapse": "urlkey",
                "limit": MAX_WAYBACK_RESULTS
            },
            headers={"User-Agent": "Theseus/1.0"},
            timeout=TIMEOUT
        )

        response.raise_for_status()

        records = response.json()

        if not isinstance(records, list) or len(records) <= 1:
            return []

        headers = records[0]

        return [
            dict(zip(headers, record))
            for record in records[1:]
            if len(record) == len(headers)
        ]

    except (
        requests.RequestException,
        ValueError,
        TypeError
    ):
        return []

def retrieve_urlscan_records(domain: str) -> list:
    try:
        result = request_json(
            URLSCAN_ENDPOINT,
            params={
                "q": f"domain:{domain}",
                "size": MAX_URLSCAN_RESULTS
            }
        )

        return result.get("results", [])

    except (
        requests.RequestException,
        ValueError,
        TypeError
    ):
        return []

def extract_urlscan_information(records: list, data: dict):
    observations = []

    for record in records:
        page = record.get("page", {})
        task = record.get("task", {})
        verdicts = record.get("verdicts", {})

        timestamp = task.get("time")
        ip_address = page.get("ip")
        hostname = page.get("domain")
        url = page.get("url")

        observation = {
            "timestamp": timestamp,
            "url": url,
            "hostname": hostname,
            "ip_address": ip_address
        }

        observations.append(observation)

        if ip_address:
            data["previously_associated_ip_addresses"].append(
                ip_address
            )

        if url:
            data["reported_malicious_urls"].append(url)

        overall_verdict = verdicts.get("overall", {})

        if overall_verdict.get("malicious") is True:
            data["malware_and_phishing_references"].append({
                "source": "urlscan.io",
                "url": url,
                "hostname": hostname,
                "ip_address": ip_address,
                "timestamp": timestamp,
                "verdict": overall_verdict
            })

            if ip_address:
                data["reported_malicious_ip_addresses"].append(
                    ip_address
                )

        if overall_verdict.get("score") is not None:
            data["threat_intelligence_identifiers"].append({
                "source": "urlscan.io",
                "scan_id": record.get("_id"),
                "score": overall_verdict.get("score"),
                "malicious": overall_verdict.get("malicious"),
                "timestamp": timestamp
            })

        if hostname:
            data[
                "historical_organisation_and_infrastructure_associations"
            ].append({
                "type": "hostname",
                "value": hostname,
                "observed_at": timestamp,
                "source": "urlscan.io"
            })

        if ip_address:
            data[
                "historical_organisation_and_infrastructure_associations"
            ].append({
                "type": "ip_address",
                "value": ip_address,
                "observed_at": timestamp,
                "source": "urlscan.io"
            })

        for key in ("engines", "community"):
            section = verdicts.get(key, {})

            if section:
                data["public_abuse_reports"].append({
                    "source": "urlscan.io",
                    "scan_id": record.get("_id"),
                    "section": key,
                    "details": section,
                    "timestamp": timestamp
                })

    return observations

def extract_wayback_information(records: list, data: dict):
    timestamps = []

    for record in records:
        timestamp = record.get("timestamp")
        original_url = record.get("original")

        if timestamp:
            timestamps.append(timestamp)

        if not original_url:
            continue

        from urllib.parse import urlparse

        hostname = urlparse(original_url).hostname

        if hostname:
            hostname = hostname.lower().rstrip(".")

            data["historical_subdomains"].append(hostname)

    if timestamps:
        data["first_seen_date"].append(
            min(timestamps)
        )

        data["last_seen_date"].append(
            max(timestamps)
        )

def extract_certificate_information(
    certificates: list,
    data: dict
):
    for certificate in certificates:
        data["historical_certificates"].append(
            certificate
        )

        for hostname in certificate.get("hostnames", []):
            data["historical_subdomains"].append(hostname)

        if certificate.get("entry_timestamp"):
            data["first_seen_date"].append(
                certificate["entry_timestamp"]
            )

            data["last_seen_date"].append(
                certificate["entry_timestamp"]
            )

def extract_observation_dates(observations: list, data: dict):
    timestamps = [
        item["timestamp"]
        for item in observations
        if item.get("timestamp")
    ]

    if timestamps:
        data["first_seen_date"].append(
            min(timestamps)
        )

        data["last_seen_date"].append(
            max(timestamps)
        )

def run(domain: str) -> dict:
    data = empty_data()
    provenance = []
    related_entities = []
    errors = []

    try:
        certificates = retrieve_certificates(domain)

        extract_certificate_information(
            certificates,
            data
        )

        provenance.append({
            "source": CRT_ENDPOINT,
            "method": "Certificate Transparency retrieval",
            "retrieved_at": datetime.now(
                timezone.utc
            ).isoformat()
        })

    except Exception as exc:
        errors.append(
            f"Certificate history retrieval failed: {exc}"
        )

    try:
        wayback_records = retrieve_wayback_records(domain)

        extract_wayback_information(
            wayback_records,
            data
        )

        provenance.append({
            "source": WAYBACK_ENDPOINT,
            "method": "Historical website snapshot retrieval",
            "retrieved_at": datetime.now(
                timezone.utc
            ).isoformat()
        })

    except Exception as exc:
        errors.append(
            f"Wayback history retrieval failed: {exc}"
        )

    try:
        urlscan_records = retrieve_urlscan_records(domain)

        observations = extract_urlscan_information(
            urlscan_records,
            data
        )

        extract_observation_dates(
            observations,
            data
        )

        provenance.append({
            "source": URLSCAN_ENDPOINT,
            "method": "Historical scan and verdict retrieval",
            "retrieved_at": datetime.now(
                timezone.utc
            ).isoformat()
        })

    except Exception as exc:
        errors.append(
            f"URLscan retrieval failed: {exc}"
        )

    for field in FIELDS:
        data[field] = unique(data[field])

    for ip_address in data["previously_associated_ip_addresses"]:
        related_entities.append({
            "type": "ip_address",
            "value": ip_address,
            "relationship": "historically_observed"
        })

    for hostname in data["historical_subdomains"]:
        if hostname != domain:
            related_entities.append({
                "type": "hostname",
                "value": hostname,
                "relationship": "historically_observed"
            })

    for certificate in data["historical_certificates"]:
        related_entities.append({
            "type": "certificate",
            "value": str(certificate.get("id")),
            "relationship": "logged_in_certificate_transparency"
        })

    related_entities = unique(related_entities)

    populated_fields = sum(
        bool(value)
        for value in data.values()
    )

    if errors and populated_fields:
        status = "partial"

    elif errors:
        status = "error"

    elif populated_fields == len(FIELDS):
        status = "success"

    elif populated_fields:
        status = "partial"

    else:
        status = "no_results"

    result = {
        "status": status,
        "module": "history",
        "data": data,
        "provenance": provenance,
        "related_entities": related_entities
    }

    if errors:
        result["error"] = errors

    return result