"""Vulnerability correlation for IP investigation evidence.

Correlates observed software/version evidence with the CISA Known
Exploited Vulnerabilities (KEV) catalogue.

This module does not exploit targets or infer vulnerabilities from open
ports alone. It requires software/product evidence from other collectors.

No third-party Python packages or API keys are required.
"""

from __future__ import annotations

import ipaddress
import json
import re
from datetime import datetime, timezone
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode
from urllib.request import Request, urlopen


MODULE_NAME = "vulnerabilities"
SOURCE_NAME = "CISA Known Exploited Vulnerabilities"
KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)
NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

TIMEOUT = 15
MAX_FEED_BYTES = 8 * 1024 * 1024
MAX_NVD_BYTES = 2 * 1024 * 1024
MAX_NVD_RESULTS = 10

VERSION_PATTERN = re.compile(
    r"(?P<product>[A-Za-z][A-Za-z0-9_. -]{1,60}?)"
    r"[/ ]+"
    r"(?P<version>\d+(?:\.\d+){1,5}(?:[-+._][A-Za-z0-9.-]+)?)"
)

def _now() -> str:
    return datetime.now(timezone.utc).isoformat()

def _error(message: str, target: str | None = None) -> dict:
    result = {
        "module": MODULE_NAME,
        "status": "error",
        "error": message,
        "observed_at": _now(),
    }
    if target is not None:
        result["target"] = target
    return result

def _fetch_json(url: str, max_bytes: int) -> tuple[dict | None, dict]:
    request = Request(
        url,
        headers={
            "Accept": "application/json",
            "User-Agent": "Theseus-OSINT/0.7",
        },
        method="GET",
    )

    try:
        with urlopen(request, timeout=TIMEOUT) as response:
            body = response.read(max_bytes + 1)

            if len(body) > max_bytes:
                return None, {
                    "status": "error",
                    "url": url,
                    "error": "Response exceeded the configured size limit.",
                }

            payload = json.loads(body.decode("utf-8"))

            if not isinstance(payload, dict):
                return None, {
                    "status": "error",
                    "url": url,
                    "error": "Source returned an unexpected JSON format.",
                }

            return payload, {
                "status": "success",
                "url": url,
                "http_status": response.status,
                "retrieved_at": _now(),
            }

    except HTTPError as exc:
        message = f"HTTP {exc.code}"
        if exc.code == 429:
            message = "Source rate limit reached."
        return None, {
            "status": "error",
            "url": url,
            "error": message,
        }
    except (URLError, TimeoutError, OSError) as exc:
        return None, {
            "status": "error",
            "url": url,
            "error": f"Connection failed: {exc}",
        }
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None, {
            "status": "error",
            "url": url,
            "error": "Source returned invalid JSON.",
        }

def _text_values(value, path: str = "") -> list[dict]:
    """Collect textual values from nested collector output."""
    found = []

    if isinstance(value, dict):
        for key, child in value.items():
            child_path = f"{path}.{key}" if path else key
            found.extend(_text_values(child, child_path))

    elif isinstance(value, list):
        for index, child in enumerate(value):
            found.extend(_text_values(child, f"{path}[{index}]"))

    elif isinstance(value, str):
        found.append({"path": path, "value": value})

    return found

def _extract_evidence(observations) -> list[dict]:
    """Extract explicit product/version strings from collector results."""
    if observations is None:
        return []

    if isinstance(observations, dict):
        status = observations.get("status")

        if status in {"error", "not_checked"}:
            return []

        module_name = observations.get("module", "")

        # Ignore fields that are not software-identification evidence.
        allowed_keys = {
            "server",
            "x-powered-by",
            "technology",
            "technologies",
            "product",
            "product_name",
            "software",
            "software_name",
            "version",
            "software_version",
            "banner",
            "service_name",
            "http_server",
        }

        candidates = []

        def walk(value, path=""):
            if isinstance(value, dict):
                for key, child in value.items():
                    key_lower = str(key).lower()
                    child_path = f"{path}.{key}" if path else str(key)

                    if key_lower in allowed_keys and isinstance(
                        child, (str, int, float)
                    ):
                        candidates.append({
                            "source": module_name or path or "observations",
                            "field": child_path,
                            "value": str(child),
                        })

                    elif isinstance(child, (dict, list)):
                        walk(child, child_path)

            elif isinstance(value, list):
                for index, child in enumerate(value):
                    walk(child, f"{path}[{index}]")

        walk(observations)
        return candidates

    if isinstance(observations, list):
        evidence = []
        for item in observations:
            evidence.extend(_extract_evidence(item))
        return evidence

    return []

def _normalise_product(value: str) -> str:
    return " ".join(value.lower().replace("_", " ").split()).strip()

def _load_kev() -> tuple[dict | None, dict]:
    return _fetch_json(KEV_URL, MAX_FEED_BYTES)

def _query_nvd(keyword: str) -> dict:
    params = urlencode({
        "keywordSearch": keyword,
        "resultsPerPage": MAX_NVD_RESULTS,
    })
    url = f"{NVD_API}?{params}"

    payload, metadata = _fetch_json(url, MAX_NVD_BYTES)

    if payload is None:
        return {
            "status": "error",
            "query": keyword,
            **metadata,
            "vulnerabilities": [],
        }

    records = payload.get("vulnerabilities", [])
    if not isinstance(records, list):
        records = []

    vulnerabilities = []

    for item in records:
        if not isinstance(item, dict):
            continue

        cve = item.get("cve", {})
        if not isinstance(cve, dict):
            continue

        descriptions = cve.get("descriptions", [])
        description = next(
            (
                entry.get("value")
                for entry in descriptions
                if isinstance(entry, dict)
                and entry.get("lang") == "en"
            ),
            None,
        )

        metrics = cve.get("metrics", {})
        cvss = None

        for metric_key in (
            "cvssMetricV40",
            "cvssMetricV31",
            "cvssMetricV30",
            "cvssMetricV2",
        ):
            entries = metrics.get(metric_key, [])
            if entries and isinstance(entries[0], dict):
                cvss_data = entries[0].get("cvssData", {})
                if isinstance(cvss_data, dict):
                    cvss = {
                        "version": cvss_data.get("version"),
                        "score": cvss_data.get("baseScore"),
                        "severity": cvss_data.get("baseSeverity"),
                        "vector": cvss_data.get("vectorString"),
                    }
                    break

        vulnerabilities.append({
            "cve_id": cve.get("id"),
            "published": cve.get("published"),
            "last_modified": cve.get("lastModified"),
            "description": description,
            "cvss": cvss,
            "nvd_url": (
                f"https://nvd.nist.gov/vuln/detail/"
                f"{quote(str(cve.get('id', '')), safe='-')}"
            ),
        })

    return {
        "status": "success",
        "query": keyword,
        "total_results": payload.get("totalResults"),
        "vulnerabilities": vulnerabilities,
        **metadata,
    }

def run(target: str, observations=None) -> dict:
    """Correlate software evidence against vulnerability information.

    Args:
        target: Investigated IPv4 or IPv6 address.
        observations: Optional collector output, or list of outputs,
            from sources such as services.py and http.py.
    """

    try:
        address = ipaddress.ip_address(str(target).strip())
    except ValueError:
        return _error("Invalid IPv4 or IPv6 address.", str(target))

    normalized_ip = str(address)

    if not address.is_global:
        return {
            "module": MODULE_NAME,
            "status": "not_checked",
            "target": normalized_ip,
            "reason": "Non-global IP addresses are not queried.",
            "observed_at": _now(),
            "evidence": [],
            "matches": [],
        }

    evidence = _extract_evidence(observations)

    if not evidence:
        return {
            "module": MODULE_NAME,
            "status": "not_checked",
            "target": normalized_ip,
            "reason": (
                "No explicit software-identification evidence was supplied. "
                "Pass observations from services.py or http.py to correlate "
                "identified products and versions."
            ),
            "observed_at": _now(),
            "evidence": [],
            "matches": [],
            "limitations": [
                "Open ports alone are not sufficient evidence of a vulnerability.",
                "A product name without a version cannot establish an affected version.",
            ],
        }

    # Fetch KEV once, then use it to enrich NVD search results.
    kev_payload, kev_metadata = _load_kev()

    kev_records = {}
    if kev_payload is not None:
        for item in kev_payload.get("vulnerabilities", []):
            if isinstance(item, dict) and item.get("cveID"):
                kev_records[item["cveID"]] = item

    # Derive explicit product/version candidates from supplied evidence.
    candidates = []

    for item in evidence:
        value = item.get("value", "")
        for match in VERSION_PATTERN.finditer(value):
            product = match.group("product").strip(" ./")
            version = match.group("version")

            if len(product) < 2:
                continue

            candidate = {
                "product": product,
                "version": version,
                "evidence_source": item.get("source"),
                "evidence_field": item.get("field"),
                "evidence_value": value,
            }

            if candidate not in candidates:
                candidates.append(candidate)

    if not candidates:
        return {
            "module": MODULE_NAME,
            "status": "not_checked",
            "target": normalized_ip,
            "reason": (
                "Evidence was supplied, but no explicit product/version "
                "pair could be extracted safely."
            ),
            "observed_at": _now(),
            "evidence": evidence,
            "matches": [],
        }

    # This is a candidate search, not a definitive affected-version check.
    # The NVD results must be reviewed against vendor affected-version data.
    searches = []
    seen_queries = set()

    for candidate in candidates:
        query = f"{candidate['product']} {candidate['version']}"

        if query.lower() in seen_queries:
            continue

        seen_queries.add(query.lower())
        searches.append(_query_nvd(query))

    return {
        "module": MODULE_NAME,
        "status": (
            "success"
            if any(item.get("status") == "success" for item in searches)
            else "error"
        ),
        "target": normalized_ip,
        "observed_at": _now(),
        "evidence": evidence,
        "software_candidates": candidates,
        "sources": {
            "kev": {
                "status": (
                    "success" if kev_payload is not None else "error"
                ),
                "url": KEV_URL,
                "catalog_version": (
                    kev_payload.get("catalogVersion")
                    if kev_payload else None
                ),
                "count": (
                    kev_payload.get("count")
                    if kev_payload else None
                ),
                "error": kev_metadata.get("error"),
            },
            "nvd": searches,
        },
        "kev_matches": [
            {
                "cve_id": cve_id,
                "vendor": record.get("vendorProject"),
                "product": record.get("product"),
                "name": record.get("vulnerabilityName"),
                "date_added": record.get("dateAdded"),
                "description": record.get("shortDescription"),
                "required_action": record.get("requiredAction"),
                "ransomware_use": record.get("knownRansomwareCampaignUse"),
                "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            }
            for cve_id, record in kev_records.items()
            if any(
                _normalise_product(candidate["product"])
                in _normalise_product(record.get("product", ""))
                or _normalise_product(record.get("product", ""))
                in _normalise_product(candidate["product"])
                for candidate in candidates
            )
        ],
        "limitations": [
            "NVD keyword results are candidates, not confirmed affected-version matches.",
            "CISA KEV matches are product-level associations, not proof that this IP is vulnerable.",
            "Vendor affected-version ranges must be checked before confirming a CVE.",
            "Software banners can be missing, misleading, or deliberately altered.",
            "This module performs no exploitation or intrusive vulnerability testing.",
        ],
    }

if __name__ == "__main__":
    import argparse
    from pprint import pprint

    parser = argparse.ArgumentParser(
        description="Correlate IP software evidence with vulnerability records."
    )
    parser.add_argument("ip", help="IPv4 or IPv6 address")
    parser.add_argument(
        "--evidence",
        help=(
            "Optional software/version string, for example "
            "'nginx/1.24.0'. Intended for isolated testing."
        ),
    )
    args = parser.parse_args()

    observations = None
    if args.evidence:
        observations = {
            "module": "manual_test",
            "status": "success",
            "server": args.evidence,
        }

    pprint(run(args.ip, observations), sort_dicts=False)