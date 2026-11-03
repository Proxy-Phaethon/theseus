import re
import socket
import requests
import tldextract

from datetime import datetime, timezone
from urllib.parse import urlparse

MODULE_NAME = "hostname"

TIMEOUT = 20
MAX_REVERSE_IP_LOOKUPS = 20

CRT_ENDPOINT = "https://crt.sh/"
DNS_ENDPOINT = "https://cloudflare-dns.com/dns-query"
REVERSE_IP_ENDPOINT = "https://api.hackertarget.com/reverseiplookup/"

HEADERS = {
    "User-Agent": "Theseus/1.0",
    "Accept": "application/json"
}

FIELDS = (
    "registered_domain",
    "parent_domain",
    "subdomains",
    "historical_subdomains",
    "nameserver_hostnames",
    "mail_server_hostnames",
    "canonical_hostnames",
    "redirect_destinations",
    "related_domains",
    "domains_sharing_ip",
    "domains_sharing_nameservers",
    "domains_sharing_certificates"
)

def empty_data() -> dict:
    return {
        "registered_domain": None,
        "parent_domain": None,
        **{
            field: []
            for field in FIELDS
            if field not in ("registered_domain", "parent_domain")
        }
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

def add_provenance(
    provenance: list,
    source: str,
    method: str
):
    provenance.append({
        "source": source,
        "method": method,
        "retrieved_at": datetime.now(
            timezone.utc
        ).isoformat()
    })

def request_json(url: str, params: dict = None) -> dict:
    response = requests.get(
        url,
        params=params,
        headers=HEADERS,
        timeout=TIMEOUT
    )

    response.raise_for_status()
    return response.json()

def get_registered_domain(domain: str):
    extracted = tldextract.extract(domain)

    if not extracted.domain or not extracted.suffix:
        return None

    return extracted.top_domain_under_public_suffix

def get_dns_records(
    domain: str,
    record_type: str
) -> tuple:
    try:
        result = request_json(
            DNS_ENDPOINT,
            params={
                "name": domain,
                "type": record_type
            }
        )

        if not isinstance(result, dict):
            raise ValueError(
                "DNS resolver returned an unexpected response."
            )

        answers = result.get("Answer", [])

        return [
            record["data"]
            for record in answers
            if isinstance(record, dict) and "data" in record
        ], [], True

    except (
        requests.RequestException,
        ValueError,
        TypeError
    ) as exc:
        return (
            [],
            [f"{record_type} lookup for {domain} failed: {exc}"],
            False
        )

def resolve_hostname(hostname: str) -> tuple:
    try:
        results = socket.getaddrinfo(
            hostname,
            None,
            type=socket.SOCK_STREAM
        )

        addresses = sorted({
            result[4][0]
            for result in results
        })

        return addresses, [], True

    except socket.gaierror as exc:
        return (
            [],
            [f"Hostname resolution for {hostname} failed: {exc}"],
            False
        )

def get_certificate_records(domain: str) -> tuple:
    try:
        result = request_json(
            CRT_ENDPOINT,
            params={
                "q": f"%.{domain}",
                "output": "json"
            }
        )

        if not isinstance(result, list):
            raise ValueError(
                "Certificate Transparency returned an unexpected response."
            )

        return result, [], True

    except (
        requests.RequestException,
        ValueError,
        TypeError
    ) as exc:
        return (
            [],
            [f"Certificate retrieval failed: {exc}"],
            False
        )

def normalise_hostname(value: str):
    if not isinstance(value, str):
        return None

    value = value.strip().lower().rstrip(".")

    if value.startswith("*."):
        value = value[2:]

    if not value or " " in value:
        return None

    try:
        extracted = tldextract.extract(value)

        if not extracted.domain or not extracted.suffix:
            return None

        return value

    except Exception:
        return None

def get_certificate_hostnames(records: list):
    hostnames = set()
    certificate_groups = {}

    for record in records:
        if not isinstance(record, dict):
            continue

        certificate_id = record.get("id")
        names = set()

        for field in (
            record.get("name_value") or "",
            record.get("common_name") or ""
        ):
            for name in field.splitlines():
                hostname = normalise_hostname(name)

                if hostname:
                    names.add(hostname)
                    hostnames.add(hostname)

        if certificate_id:
            certificate_groups[str(certificate_id)] = names

    return hostnames, certificate_groups

def get_reverse_ip_domains(ip: str) -> tuple:
    try:
        response = requests.get(
            REVERSE_IP_ENDPOINT,
            params={"q": ip},
            headers=HEADERS,
            timeout=TIMEOUT
        )

        response.raise_for_status()

        if "error" in response.text.lower():
            raise ValueError(
                f"Reverse-IP service returned an error for {ip}."
            )

        domains = set()

        for line in response.text.splitlines():
            parts = line.split(",")

            if not parts:
                continue

            hostname = normalise_hostname(parts[0])

            if hostname:
                domains.add(hostname)

        return domains, [], True

    except (
        requests.RequestException,
        ValueError
    ) as exc:
        return (
            set(),
            [f"Reverse-IP lookup for {ip} failed: {exc}"],
            False
        )

def get_redirect_destination(domain: str) -> tuple:
    for scheme in ("https", "http"):
        response = None

        try:
            response = requests.get(
                f"{scheme}://{domain}",
                headers=HEADERS,
                timeout=TIMEOUT,
                allow_redirects=True,
                stream=True
            )

            hostname = urlparse(response.url).hostname

            if hostname:
                hostname = hostname.lower().rstrip(".")

            if hostname and hostname != domain:
                return hostname, [], True

            return None, [], True

        except requests.RequestException:
            continue

        finally:
            if response is not None:
                response.close()

    return (
        None,
        [f"Unable to resolve redirect destination for {domain}."],
        False
    )

def get_nameservers(domain: str):
    records, errors, succeeded = get_dns_records(
        domain,
        "NS"
    )

    nameservers = sorted({
        value.rstrip(".").lower()
        for value in records
    })

    return nameservers, errors, succeeded

def get_mail_servers(domain: str):
    records, errors, succeeded = get_dns_records(
        domain,
        "MX"
    )

    servers = set()

    for record in records:
        parts = record.split()

        if parts:
            servers.add(
                parts[-1].rstrip(".").lower()
            )

    return sorted(servers), errors, succeeded

def get_canonical_hostnames(domain: str):
    records, errors, succeeded = get_dns_records(
        domain,
        "CNAME"
    )

    canonical = sorted({
        value.rstrip(".").lower()
        for value in records
    })

    return canonical, errors, succeeded

def find_shared_nameservers(
    candidates: set,
    target_nameservers: set
):
    shared = set()
    errors = []

    for candidate in candidates:
        candidate_nameservers, lookup_errors, succeeded = (
            get_nameservers(candidate)
        )

        errors.extend(lookup_errors)

        if succeeded and (
            set(candidate_nameservers) & target_nameservers
        ):
            shared.add(candidate)

    return sorted(shared), errors

def find_domains_sharing_certificates(
    certificate_groups: dict,
    registered_domain: str
):
    shared = set()

    for names in certificate_groups.values():
        registrable_domains = set()

        for hostname in names:
            registered = get_registered_domain(hostname)

            if registered:
                registrable_domains.add(registered)

        if registered_domain in registrable_domains:
            shared.update(
                registrable_domains - {registered_domain}
            )

    return sorted(shared)

def run(domain: str) -> dict:
    data = empty_data()
    provenance = []
    related_entities = []
    errors = []

    successful_sources = 0

    try:
        domain = domain.lower().rstrip(".")

        if not domain:
            raise ValueError("A domain must be provided.")

        registered_domain = get_registered_domain(domain)

        if not registered_domain:
            raise ValueError(
                "Unable to identify registered domain."
            )

        data["registered_domain"] = registered_domain

        extracted = tldextract.extract(domain)

        if extracted.subdomain:
            data["parent_domain"] = registered_domain

        nameservers, source_errors, ns_success = (
            get_nameservers(domain)
        )
        errors.extend(source_errors)

        if ns_success:
            successful_sources += 1
            add_provenance(
                provenance,
                DNS_ENDPOINT,
                "Nameserver record retrieval"
            )

        mail_servers, source_errors, mx_success = (
            get_mail_servers(domain)
        )
        errors.extend(source_errors)

        if mx_success:
            successful_sources += 1
            add_provenance(
                provenance,
                DNS_ENDPOINT,
                "Mail exchanger record retrieval"
            )

        canonical, source_errors, cname_success = (
            get_canonical_hostnames(domain)
        )
        errors.extend(source_errors)

        if cname_success:
            successful_sources += 1
            add_provenance(
                provenance,
                DNS_ENDPOINT,
                "Canonical hostname record retrieval"
            )

        data["nameserver_hostnames"] = nameservers
        data["mail_server_hostnames"] = mail_servers
        data["canonical_hostnames"] = canonical

        certificate_records, source_errors, crt_success = (
            get_certificate_records(registered_domain)
        )
        errors.extend(source_errors)

        certificate_hostnames, certificate_groups = (
            get_certificate_hostnames(certificate_records)
        )

        if crt_success:
            successful_sources += 1
            add_provenance(
                provenance,
                CRT_ENDPOINT,
                "Certificate Transparency hostname retrieval"
            )

        subdomains = set()
        historical_subdomains = set()

        for hostname in certificate_hostnames:
            if hostname == registered_domain:
                continue

            if hostname.endswith("." + registered_domain):
                subdomains.add(hostname)

        for record in certificate_records:
            for name in (
                record.get("name_value") or ""
            ).splitlines():
                hostname = normalise_hostname(name)

                if not hostname or hostname == registered_domain:
                    continue

                if not hostname.endswith("." + registered_domain):
                    continue

                if record.get("not_after"):
                    historical_subdomains.add(hostname)

        data["subdomains"] = sorted(subdomains)
        data["historical_subdomains"] = sorted(
            historical_subdomains
        )

        redirect, source_errors, redirect_success = (
            get_redirect_destination(domain)
        )
        errors.extend(source_errors)

        if redirect_success:
            successful_sources += 1
            add_provenance(
                provenance,
                "HTTP",
                "HTTP redirect resolution"
            )

        if redirect:
            data["redirect_destinations"] = [redirect]

        domain_ips, source_errors, resolution_success = (
            resolve_hostname(domain)
        )
        errors.extend(source_errors)

        if resolution_success:
            successful_sources += 1
            add_provenance(
                provenance,
                "System DNS resolver",
                "Target domain IP resolution"
            )

        shared_ip_domains = set()

        for ip_address in domain_ips[:MAX_REVERSE_IP_LOOKUPS]:
            discovered, source_errors, reverse_success = (
                get_reverse_ip_domains(ip_address)
            )

            errors.extend(source_errors)

            if reverse_success:
                successful_sources += 1
                shared_ip_domains.update(discovered)

        shared_ip_domains.discard(domain)
        shared_ip_domains.discard(registered_domain)

        data["domains_sharing_ip"] = sorted(
            shared_ip_domains
        )

        certificate_domains = find_domains_sharing_certificates(
            certificate_groups,
            registered_domain
        )

        data["domains_sharing_certificates"] = (
            certificate_domains
        )

        related = set(shared_ip_domains)
        related.update(certificate_domains)

        if redirect:
            related.add(redirect)

        related.discard(domain)
        related.discard(registered_domain)

        data["related_domains"] = sorted(related)

        candidates = set(shared_ip_domains)
        candidates.update(certificate_domains)

        shared_nameservers, source_errors = find_shared_nameservers(
            candidates,
            set(nameservers)
        )
        errors.extend(source_errors)

        data["domains_sharing_nameservers"] = (
            shared_nameservers
        )

        for hostname in sorted(subdomains):
            related_entities.append({
                "type": "hostname",
                "value": hostname,
                "relationship": "subdomain"
            })

        for hostname in sorted(historical_subdomains):
            related_entities.append({
                "type": "hostname",
                "value": hostname,
                "relationship": "historically_observed_subdomain"
            })

        for hostname in sorted(nameservers):
            related_entities.append({
                "type": "hostname",
                "value": hostname,
                "relationship": "nameserver"
            })

        for hostname in sorted(mail_servers):
            related_entities.append({
                "type": "hostname",
                "value": hostname,
                "relationship": "mail_server"
            })

        for hostname in sorted(canonical):
            related_entities.append({
                "type": "hostname",
                "value": hostname,
                "relationship": "canonical_hostname"
            })

        for hostname in sorted(related):
            related_entities.append({
                "type": "domain",
                "value": hostname,
                "relationship": "observed_association"
            })

        related_entities = unique(related_entities)

        for field in FIELDS:
            if isinstance(data[field], list):
                data[field] = unique(data[field])

        populated_fields = any(
            value is not None and value != []
            for value in data.values()
        )

        if errors and populated_fields:
            status = "partial"

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

    except Exception as exc:
        errors.append(str(exc))

        return make_envelope(
            status="error",
            data=data,
            provenance=provenance,
            related_entities=related_entities,
            errors=errors
        )