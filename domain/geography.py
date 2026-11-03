import socket
import ssl
import requests

from datetime import datetime, timezone
from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse

MODULE_NAME = "geography"

RDAP_ENDPOINT = "https://rdap.org/domain/{}"
DNS_ENDPOINT = "https://cloudflare-dns.com/dns-query"
GEO_ENDPOINT = "https://ipwho.is/{}"

TIMEOUT = 15
MAX_GEOLOOKUPS = 30

FIELDS = (
    "registrant_country",
    "registrant_region",
    "registrant_city",
    "registrant_address",
    "registrant_postal_code",
    "hosting_country",
    "hosting_city",
    "ip_geolocation",
    "nameserver_locations",
    "mail_server_locations",
    "cdn_edge_locations",
    "certificate_organisation_country",
    "public_business_addresses",
    "website_contact_geography",
)

def empty_data() -> dict:
    return {
        "registrant_country": None,
        "registrant_region": None,
        "registrant_city": None,
        "registrant_address": None,
        "registrant_postal_code": None,
        "hosting_country": [],
        "hosting_city": [],
        "ip_geolocation": [],
        "nameserver_locations": [],
        "mail_server_locations": [],
        "cdn_edge_locations": [],
        "certificate_organisation_country": None,
        "public_business_addresses": [],
        "website_contact_geography": [],
    }

def timestamp() -> str:
    return datetime.now(timezone.utc).isoformat()

def make_envelope(
    data: dict,
    status: str,
    provenance: list,
    related_entities: list,
    errors: list,
) -> dict:
    return {
        "module": MODULE_NAME,
        "status": status,
        "data": data,
        "provenance": provenance,
        "related_entities": related_entities,
        "errors": errors,
    }

def request_json(url: str, **kwargs) -> dict:
    response = requests.get(
        url,
        timeout=TIMEOUT,
        **kwargs,
    )

    response.raise_for_status()
    return response.json()

def get_dns_records(domain: str, record_type: str) -> list:
    result = request_json(
        DNS_ENDPOINT,
        params={
            "name": domain,
            "type": record_type,
        },
        headers={"Accept": "application/dns-json"},
    )

    return [
        record["data"]
        for record in result.get("Answer", [])
        if "data" in record
    ]

def get_ip_addresses(hostname: str) -> list:
    results = socket.getaddrinfo(
        hostname,
        None,
        type=socket.SOCK_STREAM,
    )

    return sorted({
        result[4][0]
        for result in results
    })

def geolocate_ip(ip: str) -> dict | None:
    result = request_json(
        GEO_ENDPOINT.format(ip),
    )

    if not result.get("success"):
        raise ValueError(
            f"Geolocation provider returned no result for {ip}."
        )

    connection = result.get("connection") or {}

    return {
        "ip": ip,
        "country": result.get("country"),
        "region": result.get("region"),
        "city": result.get("city"),
        "postal_code": result.get("postal"),
        "latitude": result.get("latitude"),
        "longitude": result.get("longitude"),
        "isp": connection.get("isp"),
    }

def get_rdap_location(domain: str) -> dict | None:
    result = request_json(
        RDAP_ENDPOINT.format(domain),
    )

    for entity in result.get("entities", []):
        if "registrant" not in entity.get("roles", []):
            continue

        vcard = entity.get("vcardArray", [])

        if len(vcard) < 2 or not isinstance(vcard[1], list):
            continue

        for item in vcard[1]:
            if (
                isinstance(item, list)
                and len(item) >= 4
                and item[0] == "adr"
                and isinstance(item[3], list)
            ):
                address = item[3]

                return {
                    "address": ", ".join(
                        str(part)
                        for part in address
                        if part
                    ) or None,
                    "city": address[3] or None,
                    "region": address[4] or None,
                    "postal_code": address[5] or None,
                    "country": address[6] or None,
                }

    return None

class WebsiteParser(HTMLParser):
    def __init__(self):
        super().__init__()

        self.jsonld = []
        self.links = []
        self.in_jsonld = False
        self.current_script = ""

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)

        if (
            tag == "script"
            and attrs.get("type") == "application/ld+json"
        ):
            self.in_jsonld = True
            self.current_script = ""

        if tag == "a" and attrs.get("href"):
            href = attrs["href"]

            if any(
                keyword in href.lower()
                for keyword in ("contact", "about", "location")
            ):
                self.links.append(href)

    def handle_data(self, data):
        if self.in_jsonld:
            self.current_script += data

    def handle_endtag(self, tag):
        if tag == "script" and self.in_jsonld:
            self.jsonld.append(self.current_script)
            self.in_jsonld = False

def collect_addresses(data) -> list:
    addresses = []

    if isinstance(data, list):
        for item in data:
            addresses.extend(collect_addresses(item))

    elif isinstance(data, dict):
        address = data.get("address")

        if isinstance(address, dict):
            fields = (
                "streetAddress",
                "addressLocality",
                "addressRegion",
                "postalCode",
                "addressCountry",
            )

            extracted = {
                key: address[key]
                for key in fields
                if address.get(key)
            }

            if extracted:
                addresses.append(extracted)

        elif isinstance(address, str):
            addresses.append({"address": address})

        for key, value in data.items():
            if key == "address":
                continue

            if isinstance(value, (dict, list)):
                addresses.extend(collect_addresses(value))

    return addresses

def extract_website_addresses(domain: str) -> tuple[list, list, list]:
    base_url = f"https://{domain}/"
    base_host = urlparse(base_url).hostname

    urls = [base_url]
    addresses = []
    errors = []
    visited = set()

    session = requests.Session()

    headers = {
        "User-Agent": "Theseus/1.0 (public domain research)",
    }

    while urls and len(visited) < 6:
        url = urls.pop(0)

        if url in visited:
            continue

        visited.add(url)

        try:
            response = session.get(
                url,
                headers=headers,
                timeout=TIMEOUT,
            )

            response.raise_for_status()

            if urlparse(response.url).hostname != base_host:
                continue

            if "text/html" not in response.headers.get(
                "Content-Type", ""
            ):
                continue

            parser = WebsiteParser()
            parser.feed(response.text)

            for script in parser.jsonld:
                try:
                    structured_data = __import__("json").loads(script)

                    addresses.extend(
                        collect_addresses(structured_data)
                    )

                except (ValueError, TypeError):
                    continue

            for link in parser.links[:5]:
                candidate = urljoin(response.url, link)

                if (
                    urlparse(candidate).hostname == base_host
                    and candidate not in visited
                ):
                    urls.append(candidate)

        except requests.RequestException as exc:
            errors.append(
                f"Website retrieval failed ({url}): {exc}"
            )

    unique_addresses = []

    for address in addresses:
        if address not in unique_addresses:
            unique_addresses.append(address)

    contact_geography = [
        {
            "source": "website structured data",
            **address,
        }
        for address in unique_addresses
    ]

    session.close()

    return unique_addresses, contact_geography, errors

def get_certificate_country(domain: str) -> str | None:
    context = ssl.create_default_context()

    with socket.create_connection(
        (domain, 443),
        timeout=TIMEOUT,
    ) as connection:

        with context.wrap_socket(
            connection,
            server_hostname=domain,
        ) as secure_socket:

            certificate = secure_socket.getpeercert()

    for group in certificate.get("subject", []):
        for key, value in group:
            if key == "countryName":
                return value

    return None

def add_provenance(
    provenance: list,
    source: str,
    method: str,
) -> None:
    provenance.append({
        "source": source,
        "method": method,
        "retrieved_at": timestamp(),
    })

def has_data(value) -> bool:
    if value is None:
        return False

    if isinstance(value, (list, dict, tuple, set)):
        return bool(value)

    return True

def run(domain: str) -> dict:
    data = empty_data()
    provenance = []
    related_entities = []
    errors = []

    successful_sources = 0
    geolookups = 0

    try:
        registrant = get_rdap_location(domain)

        if registrant:
            data["registrant_country"] = registrant["country"]
            data["registrant_region"] = registrant["region"]
            data["registrant_city"] = registrant["city"]
            data["registrant_address"] = registrant["address"]
            data["registrant_postal_code"] = registrant["postal_code"]

            successful_sources += 1

        add_provenance(
            provenance,
            RDAP_ENDPOINT.format(domain),
            "RDAP registrant address extraction",
        )

    except Exception as exc:
        errors.append(f"RDAP retrieval failed: {exc}")

    try:
        domain_ips = get_ip_addresses(domain)
        ip_locations = []

        for ip in domain_ips:
            if geolookups >= MAX_GEOLOOKUPS:
                errors.append(
                    "Geolocation lookup limit reached."
                )
                break

            try:
                location = geolocate_ip(ip)
                geolookups += 1

                if location:
                    ip_locations.append(location)

            except Exception as exc:
                errors.append(
                    f"IP geolocation failed ({ip}): {exc}"
                )
                geolookups += 1

        data["ip_geolocation"] = ip_locations

        data["hosting_country"] = sorted({
            item["country"]
            for item in ip_locations
            if item["country"]
        })

        data["hosting_city"] = sorted({
            item["city"]
            for item in ip_locations
            if item["city"]
        })

        successful_sources += 1

        add_provenance(
            provenance,
            GEO_ENDPOINT,
            "IP geolocation",
        )

        for location in ip_locations:
            related_entities.append({
                "type": "ip_address",
                "value": location["ip"],
                "relationship": "resolved_from_target_domain",
            })

    except Exception as exc:
        errors.append(
            f"Domain IP retrieval failed: {exc}"
        )

    try:
        nameservers = get_dns_records(domain, "NS")
        nameserver_locations = []

        for nameserver in nameservers:
            hostname = nameserver.rstrip(".").lower()

            try:
                addresses = get_ip_addresses(hostname)
            except socket.gaierror as exc:
                errors.append(
                    f"Nameserver resolution failed ({hostname}): {exc}"
                )
                continue

            for ip in addresses:
                if geolookups >= MAX_GEOLOOKUPS:
                    break

                try:
                    location = geolocate_ip(ip)
                    geolookups += 1

                    if location:
                        nameserver_locations.append({
                            "hostname": hostname,
                            **location,
                        })

                except Exception as exc:
                    errors.append(
                        f"Nameserver geolocation failed ({ip}): {exc}"
                    )
                    geolookups += 1

        data["nameserver_locations"] = nameserver_locations
        successful_sources += 1

        add_provenance(
            provenance,
            DNS_ENDPOINT,
            "DNS nameserver and IP geolocation inspection",
        )

    except Exception as exc:
        errors.append(
            f"Nameserver inspection failed: {exc}"
        )

    try:
        mail_servers = get_dns_records(domain, "MX")
        mail_locations = []

        for record in mail_servers:
            parts = record.split()
            hostname = parts[-1].rstrip(".").lower() if parts else None

            if not hostname:
                continue

            try:
                addresses = get_ip_addresses(hostname)
            except socket.gaierror as exc:
                errors.append(
                    f"Mail server resolution failed ({hostname}): {exc}"
                )
                continue

            for ip in addresses:
                if geolookups >= MAX_GEOLOOKUPS:
                    break

                try:
                    location = geolocate_ip(ip)
                    geolookups += 1

                    if location:
                        mail_locations.append({
                            "hostname": hostname,
                            **location,
                        })

                except Exception as exc:
                    errors.append(
                        f"Mail server geolocation failed ({ip}): {exc}"
                    )
                    geolookups += 1

        data["mail_server_locations"] = mail_locations
        successful_sources += 1

        add_provenance(
            provenance,
            DNS_ENDPOINT,
            "DNS mail server and IP geolocation inspection",
        )

    except Exception as exc:
        errors.append(
            f"Mail server inspection failed: {exc}"
        )

    data["cdn_edge_locations"] = [
        item
        for item in data["ip_geolocation"]
        if any(
            keyword in (item.get("isp") or "").lower()
            for keyword in (
                "cloudflare",
                "akamai",
                "fastly",
                "amazon",
                "cloudfront",
            )
        )
    ]

    try:
        certificate_country = get_certificate_country(domain)

        data["certificate_organisation_country"] = (
            certificate_country
        )

        successful_sources += 1

        add_provenance(
            provenance,
            f"https://{domain}",
            "TLS certificate subject country inspection",
        )

    except Exception as exc:
        errors.append(
            f"TLS certificate inspection failed: {exc}"
        )

    try:
        addresses, contact_geography, website_errors = (
            extract_website_addresses(domain)
        )

        data["public_business_addresses"] = addresses
        data["website_contact_geography"] = contact_geography
        errors.extend(website_errors)

        successful_sources += 1

        add_provenance(
            provenance,
            f"https://{domain}",
            "Website JSON-LD structured address extraction",
        )

    except Exception as exc:
        errors.append(
            f"Website geography extraction failed: {exc}"
        )

    populated_fields = sum(
        has_data(value)
        for value in data.values()
    )

    if errors and populated_fields:
        status = "partial"

    elif errors and successful_sources == 0:
        status = "error"

    elif populated_fields:
        status = "success"

    elif successful_sources:
        status = "no_results"

    else:
        status = "error"

    return {
        "module": MODULE_NAME,
        "status": status,
        "data": data,
        "provenance": provenance,
        "related_entities": related_entities,
        "errors": errors,
    }