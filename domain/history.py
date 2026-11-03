import requests

from datetime import datetime, timezone
from urllib.parse import urlparse

MODULE_NAME = "history"

CRT_ENDPOINT = "https://crt.sh/"
WAYBACK_ENDPOINT = "https://web.archive.org/cdx/search/cdx"
URLSCAN_ENDPOINT = "https://urlscan.io/api/v1/search/"

TIMEOUT = 20
MAX_URLSCAN_RESULTS = 100
MAX_WAYBACK_RESULTS = 1000

HEADERS = {
    "User-Agent": "Theseus/1.0",
    "Accept": "application/json"
}

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

def make_envelope(
    status: str,
    data: dict = None,
    provenance: list = None,
    related_entities: list = None,
    errors: list = None
) -> dict:
    return {
        "module": MODULE_NAME,
        "status": status,
        "data": data if data is not None else empty_data(),
        "provenance": provenance if provenance is not None else [],
        "related_entities": (
            related_entities if related_entities is not None else []
        ),
        "errors": errors if errors is not None else []
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

def parse_timestamp(value: str):
    if not value:
        return None

    value = str(value).strip()

    try:
        return datetime.strptime(
            value,
            "%Y%m%d%H%M%S"
        ).replace(tzinfo=timezone.utc)
    except ValueError:
        pass

    try:
        parsed = datetime.fromisoformat(
            value.replace("Z", "+00:00")
        )

        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)

        return parsed.astimezone(timezone.utc)

    except ValueError:
        return None

def record_observation_date(timestamp: str, dates: list):
    parsed = parse_timestamp(timestamp)

    if parsed:
        dates.append(parsed)

def request_json(url: str, params: dict = None) -> dict:
    response = requests.get(
        url,
        params=params,
        headers=HEADERS,
        timeout=TIMEOUT
    )

    response.raise_for_status()

    return response.json()

def retrieve_certificates(domain: str) -> tuple:
    certificates = {}
    errors = []
    successful_queries = 0

    queries = [
        domain,
        f"%.{domain}"
    ]

    for query in queries:
        try:
            records = request_json(
                CRT_ENDPOINT,
                params={
                    "q": query,
                    "output": "json"
                }
            )

            if not isinstance(records, list):
                raise ValueError(
                    "Certificate Transparency returned an unexpected response."
                )

            successful_queries += 1

            for record in records:
                certificate_id = record.get("id")

                if not certificate_id:
                    continue

                hostnames = sorted(set(
                    name.strip().lower().rstrip(".")
                    for name in (
                        record.get("name_value") or ""
                    ).splitlines()
                    if name.strip()
                ))

                certificates[str(certificate_id)] = {
                    "id": certificate_id,
                    "issuer": record.get("issuer_name"),
                    "common_name": record.get("common_name"),
                    "hostnames": hostnames,
                    "not_before": record.get("not_before"),
                    "not_after": record.get("not_after"),
                    "entry_timestamp": record.get("entry_timestamp")
                }

        except (
            requests.RequestException,
            ValueError,
            TypeError
        ) as exc:
            errors.append(
                f"Certificate Transparency query '{query}' failed: {exc}"
            )

    return (
        list(certificates.values()),
        errors,
        successful_queries > 0
    )

def retrieve_wayback_records(domain: str) -> tuple:
    try:
        records = request_json(
            WAYBACK_ENDPOINT,
            params={
                "url": f"{domain}/*",
                "output": "json",
                "fl": "timestamp,original,statuscode,mimetype",
                "filter": "statuscode:200",
                "collapse": "urlkey",
                "limit": MAX_WAYBACK_RESULTS
            }
        )

        if not isinstance(records, list):
            raise ValueError(
                "Internet Archive returned an unexpected response."
            )

        if len(records) <= 1:
            return [], [], True

        headers = records[0]

        results = [
            dict(zip(headers, record))
            for record in records[1:]
            if len(record) == len(headers)
        ]

        return results, [], True

    except (
        requests.RequestException,
        ValueError,
        TypeError
    ) as exc:
        return (
            [],
            [f"Wayback retrieval failed: {exc}"],
            False
        )

def retrieve_urlscan_records(domain: str) -> tuple:
    try:
        result = request_json(
            URLSCAN_ENDPOINT,
            params={
                "q": f"domain:{domain}",
                "size": MAX_URLSCAN_RESULTS
            }
        )

        if not isinstance(result, dict):
            raise ValueError(
                "URLscan returned an unexpected response."
            )

        records = result.get("results", [])

        if not isinstance(records, list):
            raise ValueError(
                "URLscan returned an invalid results collection."
            )

        return records, [], True

    except (
        requests.RequestException,
        ValueError,
        TypeError
    ) as exc:
        return (
            [],
            [f"URLscan retrieval failed: {exc}"],
            False
        )

def extract_urlscan_information(
    records: list,
    data: dict,
    observation_dates: list
) -> list:
    observations = []

    for record in records:
        if not isinstance(record, dict):
            continue

        page = record.get("page") or {}
        task = record.get("task") or {}
        verdicts = record.get("verdicts") or {}

        if not isinstance(page, dict):
            page = {}

        if not isinstance(task, dict):
            task = {}

        if not isinstance(verdicts, dict):
            verdicts = {}

        timestamp = task.get("time")
        ip_address = page.get("ip")
        hostname = page.get("domain")
        url = page.get("url")

        if hostname:
            hostname = hostname.lower().rstrip(".")

        observation = {
            "timestamp": timestamp,
            "url": url,
            "hostname": hostname,
            "ip_address": ip_address
        }

        observations.append(observation)

        if timestamp:
            record_observation_date(
                timestamp,
                observation_dates
            )

        if ip_address:
            data["previously_associated_ip_addresses"].append(
                ip_address
            )

        overall_verdict = verdicts.get("overall") or {}

        if not isinstance(overall_verdict, dict):
            overall_verdict = {}

        malicious = overall_verdict.get("malicious") is True

        if malicious:
            if url:
                data["reported_malicious_urls"].append(url)

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
                "malicious": malicious,
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
            section = verdicts.get(key) or {}

            if section:
                data["public_abuse_reports"].append({
                    "source": "urlscan.io",
                    "scan_id": record.get("_id"),
                    "section": key,
                    "details": section,
                    "timestamp": timestamp
                })

    return observations

def extract_wayback_information(
    records: list,
    data: dict,
    observation_dates: list
):
    for record in records:
        timestamp = record.get("timestamp")
        original_url = record.get("original")

        if timestamp:
            record_observation_date(
                timestamp,
                observation_dates
            )

        if not original_url:
            continue

        hostname = urlparse(original_url).hostname

        if hostname:
            hostname = hostname.lower().rstrip(".")

            if hostname:
                data["historical_subdomains"].append(hostname)

def extract_certificate_information(
    certificates: list,
    data: dict,
    observation_dates: list
):
    for certificate in certificates:
        data["historical_certificates"].append(
            certificate
        )

        for hostname in certificate.get("hostnames", []):
            data["historical_subdomains"].append(hostname)

        timestamp = certificate.get("entry_timestamp")

        if timestamp:
            record_observation_date(
                timestamp,
                observation_dates
            )

def populate_observation_dates(
    observation_dates: list,
    data: dict
):
    if not observation_dates:
        return

    data["first_seen_date"].append(
        min(observation_dates).isoformat()
    )

    data["last_seen_date"].append(
        max(observation_dates).isoformat()
    )

def build_related_entities(
    domain: str,
    data: dict
) -> list:
    related_entities = []

    for ip_address in data["previously_associated_ip_addresses"]:
        related_entities.append({
            "type": "ip_address",
            "value": ip_address,
            "relationship": "observed_in_historical_scan"
        })

    for hostname in data["historical_subdomains"]:
        if hostname != domain:
            related_entities.append({
                "type": "hostname",
                "value": hostname,
                "relationship": "observed_in_historical_record"
            })

    for certificate in data["historical_certificates"]:
        certificate_id = certificate.get("id")

        if certificate_id is not None:
            related_entities.append({
                "type": "certificate",
                "value": str(certificate_id),
                "relationship": "logged_in_certificate_transparency"
            })

    return unique(related_entities)

def run(domain: str) -> dict:
    data = empty_data()
    provenance = []
    errors = []
    observation_dates = []

    successful_sources = 0

    certificates, source_errors, succeeded = retrieve_certificates(
        domain
    )

    errors.extend(source_errors)

    if succeeded:
        successful_sources += 1

        provenance.append({
            "source": CRT_ENDPOINT,
            "method": "Certificate Transparency retrieval",
            "retrieved_at": datetime.now(
                timezone.utc
            ).isoformat()
        })

    extract_certificate_information(
        certificates,
        data,
        observation_dates
    )

    wayback_records, source_errors, succeeded = (
        retrieve_wayback_records(domain)
    )

    errors.extend(source_errors)

    if succeeded:
        successful_sources += 1

        provenance.append({
            "source": WAYBACK_ENDPOINT,
            "method": "Historical website snapshot retrieval",
            "retrieved_at": datetime.now(
                timezone.utc
            ).isoformat()
        })

    extract_wayback_information(
        wayback_records,
        data,
        observation_dates
    )

    urlscan_records, source_errors, succeeded = (
        retrieve_urlscan_records(domain)
    )

    errors.extend(source_errors)

    if succeeded:
        successful_sources += 1

        provenance.append({
            "source": URLSCAN_ENDPOINT,
            "method": "Historical scan and verdict retrieval",
            "retrieved_at": datetime.now(
                timezone.utc
            ).isoformat()
        })

    extract_urlscan_information(
        urlscan_records,
        data,
        observation_dates
    )

    populate_observation_dates(
        observation_dates,
        data
    )

    for field in FIELDS:
        data[field] = unique(data[field])

    related_entities = build_related_entities(
        domain,
        data
    )

    populated_fields = any(
        bool(value)
        for value in data.values()
    )

    if errors and populated_fields:
        status = "partial"

    elif errors and successful_sources == 0:
        status = "error"

    elif errors:
        status = "error"

    elif populated_fields:
        status = "success"

    else:
        status = "no_results"

    return make_envelope(
        status=status,
        data=data,
        provenance=provenance,
        related_entities=related_entities,
        errors=errors
    )