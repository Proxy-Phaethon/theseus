import re
import socket
import requests
import tldextract

from urllib.parse import urljoin, urlparse

TIMEOUT = 20

CRT_ENDPOINT = "https://crt.sh/"
DNS_ENDPOINT = "https://cloudflare-dns.com/dns-query"
REVERSE_IP_ENDPOINT = "https://api.hackertarget.com/reverseiplookup/"

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

def empty_data():
    return {field: "none" for field in FIELDS}

def request_json(url, params=None):
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

def get_registered_domain(domain):

    extracted = tldextract.extract(domain)

    if not extracted.domain or not extracted.suffix:
        return None

    return extracted.top_domain_under_public_suffix

def get_dns_records(domain, record_type):
    try:
        result = request_json(
            DNS_ENDPOINT,
            params={
                "name": domain,
                "type": record_type
            }
        )

        return [
            record["data"]
            for record in result.get("Answer", [])
            if "data" in record
        ]

    except (requests.RequestException, ValueError):
        return []

def resolve_hostname(hostname):
    addresses = set()

    try:
        results = socket.getaddrinfo(
            hostname,
            None,
            type=socket.SOCK_STREAM
        )

        addresses.update(
            result[4][0] for result in results
        )

    except socket.gaierror:
        pass

    return sorted(addresses)

def get_certificate_records(domain):
    try:
        result = request_json(
            CRT_ENDPOINT,
            params={
                "q": f"%.{domain}",
                "output": "json"
            }
        )

        return result if isinstance(result, list) else []

    except (requests.RequestException, ValueError):
        return []

def normalise_hostname(value):
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

def get_certificate_hostnames(records):
    hostnames = set()
    historical = set()
    certificate_groups = {}

    for record in records:

        certificate_id = record.get("id")

        names = set()

        for field in (
            record.get("name_value", ""),
            record.get("common_name", "")
        ):

            for name in field.splitlines():

                hostname = normalise_hostname(name)

                if hostname:
                    names.add(hostname)
                    hostnames.add(hostname)

        if certificate_id:
            certificate_groups[certificate_id] = names

    return hostnames, historical, certificate_groups

def get_reverse_ip_domains(ip):
    try:
        response = requests.get(
            REVERSE_IP_ENDPOINT,
            params={"q": ip},
            headers={"User-Agent": "Theseus/1.0"},
            timeout=TIMEOUT
        )

        response.raise_for_status()

        if "error" in response.text.lower():
            return set()

        domains = set()

        for line in response.text.splitlines():

            parts = line.split(",")

            if not parts:
                continue

            hostname = normalise_hostname(parts[0])

            if hostname:
                domains.add(hostname)

        return domains

    except requests.RequestException:
        return set()

def get_redirect_destination(domain):
    for scheme in ("https", "http"):

        try:
            response = requests.get(
                f"{scheme}://{domain}",
                headers={"User-Agent": "Theseus/1.0"},
                timeout=TIMEOUT,
                allow_redirects=True,
                stream=True
            )

            destination = response.url
            response.close()

            hostname = urlparse(destination).hostname

            if hostname and hostname.lower() != domain.lower():
                return hostname.lower()

            return None

        except requests.RequestException:
            continue

    return None

def get_nameservers(domain):
    return sorted({
        value.rstrip(".").lower()
        for value in get_dns_records(domain, "NS")
    })

def get_mail_servers(domain):
    servers = set()

    for record in get_dns_records(domain, "MX"):

        parts = record.split()

        if parts:
            servers.add(parts[-1].rstrip(".").lower())

    return sorted(servers)

def get_canonical_hostnames(domain):
    return sorted({
        value.rstrip(".").lower()
        for value in get_dns_records(domain, "CNAME")
    })

def find_shared_nameservers(candidates, target_nameservers):
    shared = set()

    for candidate in candidates:

        candidate_nameservers = set(
            get_nameservers(candidate)
        )

        if candidate_nameservers & target_nameservers:
            shared.add(candidate)

    return sorted(shared)

def find_domains_sharing_certificates(
    certificate_groups,
    registered_domain
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

    try:
        domain = domain.lower().rstrip(".")

        registered_domain = get_registered_domain(domain)

        if not registered_domain:
            raise ValueError("Unable to identify registered domain.")

        data["registered_domain"] = registered_domain

        extracted = tldextract.extract(domain)

        if extracted.subdomain:
            data["parent_domain"] = registered_domain

        nameservers = get_nameservers(domain)
        mail_servers = get_mail_servers(domain)
        canonical = get_canonical_hostnames(domain)

        if nameservers:
            data["nameserver_hostnames"] = nameservers

        if mail_servers:
            data["mail_server_hostnames"] = mail_servers

        if canonical:
            data["canonical_hostnames"] = canonical

        certificate_records = get_certificate_records(
            registered_domain
        )

        certificate_hostnames, _, certificate_groups = (
            get_certificate_hostnames(certificate_records)
        )

        subdomains = set()
        historical_subdomains = set()

        for hostname in certificate_hostnames:

            if hostname == registered_domain:
                continue

            if hostname.endswith("." + registered_domain):
                subdomains.add(hostname)

        for record in certificate_records:

            names = record.get("name_value", "").splitlines()

            for name in names:

                hostname = normalise_hostname(name)

                if not hostname or hostname == registered_domain:
                    continue

                if not hostname.endswith("." + registered_domain):
                    continue

                if record.get("not_after"):
                    historical_subdomains.add(hostname)

        if subdomains:
            data["subdomains"] = sorted(subdomains)

        if historical_subdomains:
            data["historical_subdomains"] = sorted(
                historical_subdomains
            )

        if certificate_records:
            provenance.append({
                "source": "crt.sh",
                "description": "Certificate Transparency records",
                "url": CRT_ENDPOINT
            })

        redirect = get_redirect_destination(domain)

        if redirect:
            data["redirect_destinations"] = [redirect]

        domain_ips = set(resolve_hostname(domain))

        for hostname in nameservers + mail_servers + canonical:
            domain_ips.update(resolve_hostname(hostname))

        shared_ip_domains = set()

        for ip in resolve_hostname(domain):
            shared_ip_domains.update(
                get_reverse_ip_domains(ip)
            )

        shared_ip_domains.discard(domain)
        shared_ip_domains.discard(registered_domain)

        if shared_ip_domains:
            data["domains_sharing_ip"] = sorted(
                shared_ip_domains
            )

        certificate_domains = find_domains_sharing_certificates(
            certificate_groups,
            registered_domain
        )

        if certificate_domains:
            data["domains_sharing_certificates"] = (
                certificate_domains
            )

        related = set(shared_ip_domains)
        related.update(certificate_domains)

        if redirect:
            related.add(redirect)

        related.discard(domain)
        related.discard(registered_domain)

        if related:
            data["related_domains"] = sorted(related)

        candidates = set(shared_ip_domains)
        candidates.update(certificate_domains)

        shared_nameservers = find_shared_nameservers(
            candidates,
            set(nameservers)
        )

        if shared_nameservers:
            data["domains_sharing_nameservers"] = (
                shared_nameservers
            )

        if nameservers or mail_servers or canonical:
            provenance.append({
                "source": "Cloudflare DNS",
                "description": "DNS hostname records",
                "url": DNS_ENDPOINT
            })

        if shared_ip_domains:
            provenance.append({
                "source": "HackerTarget",
                "description": "Reverse IP lookup",
                "url": REVERSE_IP_ENDPOINT
            })

        if redirect:
            provenance.append({
                "source": "HTTP",
                "description": "Redirect resolution"
            })

        for hostname in sorted(subdomains):
            related_entities.append({
                "type": "hostname",
                "value": hostname,
                "relationship": "subdomain"
            })

        for hostname in sorted(related):
            related_entities.append({
                "type": "domain",
                "value": hostname,
                "relationship": "related domain"
            })

        populated = sum(
            value != "none"
            for value in data.values()
        )

        status = (
            "success"
            if populated == len(FIELDS)
            else "partial" if populated else "error"
        )

        return {
            "status": status,
            "module": "hostname",
            "data": data,
            "provenance": provenance,
            "related_entities": related_entities
        }

    except Exception as exc:

        return {
            "status": "error",
            "module": "hostname",
            "data": data,
            "provenance": provenance,
            "related_entities": related_entities,
            "error": str(exc)
        }