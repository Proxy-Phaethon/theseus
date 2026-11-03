import json
import socket
import requests

from datetime import datetime, timezone
from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse

MODULE_NAME = "geography"

RDAP_ENDPOINT = "https://rdap.org/domain/{}"
TIMEOUT = 15
MAX_WEBSITE_PAGES = 6
MAX_PAGE_SIZE = 5 * 1024 * 1024

FIELDS = (
    "registrant_location",
    "published_locations",
    "ip_addresses",
    "nameserver_ip_addresses",
    "mail_server_ip_addresses",
)

def empty_data() -> dict:
    return {
        "registrant_location": {
            "country": None,
            "region": None,
            "city": None,
            "address": None,
            "postal_code": None,
        },
        "published_locations": [],
        "ip_addresses": [],
        "nameserver_ip_addresses": [],
        "mail_server_ip_addresses": [],
    }

def timestamp() -> str:
    return datetime.now(timezone.utc).isoformat()

def make_envelope(
    status: str,
    data: dict = None,
    provenance: list = None,
    related_entities: list = None,
    errors: list = None,
) -> dict:
    return {
        "module": MODULE_NAME,
        "status": status,
        "data": data if data is not None else empty_data(),
        "provenance": provenance if provenance is not None else [],
        "related_entities": (
            related_entities if related_entities is not None else []
        ),
        "errors": errors if errors is not None else [],
    }

def unique(values: list) -> list:
    result = []
    seen = set()

    for value in values:
        if value is None:
            continue

        if isinstance(value, dict):
            key = json.dumps(
                value,
                sort_keys=True,
                default=str,
            ).lower()
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
        key=lambda item: str(item).lower(),
    )

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

def request_json(url: str, **kwargs) -> dict:
    response = requests.get(
        url,
        timeout=TIMEOUT,
        headers={
            "User-Agent": "Theseus/1.0",
            **kwargs.pop("headers", {}),
        },
        **kwargs,
    )

    try:
        response.raise_for_status()
        return response.json()
    finally:
        response.close()

def get_rdap_location(domain: str) -> dict | None:
    result = request_json(
        RDAP_ENDPOINT.format(domain),
    )

    for entity in result.get("entities", []):
        if "registrant" not in entity.get("roles", []):
            continue

        vcard = entity.get("vcardArray", [])

        if (
            len(vcard) < 2
            or not isinstance(vcard[1], list)
        ):
            continue

        for item in vcard[1]:
            if (
                not isinstance(item, list)
                or len(item) < 4
                or item[0] != "adr"
                or not isinstance(item[3], list)
            ):
                continue

            address = item[3]

            return {
                "address": ", ".join(
                    str(part).strip()
                    for part in address
                    if part
                ) or None,
                "city": address[3] or None if len(address) > 3 else None,
                "region": address[4] or None if len(address) > 4 else None,
                "postal_code": address[5] or None if len(address) > 5 else None,
                "country": address[6] or None if len(address) > 6 else None,
            }

    return None

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

def get_dns_records(
    domain: str,
    record_type: str,
) -> list:
    result = request_json(
        "https://cloudflare-dns.com/dns-query",
        params={
            "name": domain,
            "type": record_type,
        },
        headers={
            "Accept": "application/dns-json",
        },
    )

    if not isinstance(result, dict):
        raise ValueError("Unexpected DNS response.")

    if result.get("Status") not in (0, 3):
        raise ValueError("DNS resolver returned an unsuccessful status.")

    return [
        record["data"]
        for record in result.get("Answer", [])
        if isinstance(record, dict) and "data" in record
    ]

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
            and attrs.get("type", "").lower() == "application/ld+json"
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

        elif isinstance(address, str) and address.strip():
            addresses.append({
                "address": address.strip(),
            })

        for key, value in data.items():
            if key == "address":
                continue

            if isinstance(value, (dict, list)):
                addresses.extend(collect_addresses(value))

    return addresses

def normalise_address(address: dict) -> dict:
    field_mapping = {
        "streetAddress": "address",
        "addressLocality": "city",
        "addressRegion": "region",
        "postalCode": "postal_code",
        "addressCountry": "country",
    }

    normalised = {
        "country": None,
        "region": None,
        "city": None,
        "address": None,
        "postal_code": None,
    }

    if "address" in address:
        normalised["address"] = address["address"]

    for original, canonical in field_mapping.items():
        if address.get(original):
            normalised[canonical] = address[original]

    return normalised

def extract_website_addresses(domain: str) -> tuple:
    base_url = f"https://{domain}/"
    base_host = urlparse(base_url).hostname

    urls = [base_url]
    addresses = []
    errors = []
    visited = set()

    headers = {
        "User-Agent": "Theseus/1.0 (public domain research)",
    }

    with requests.Session() as session:
        while urls and len(visited) < MAX_WEBSITE_PAGES:
            url = urls.pop(0)

            if url in visited:
                continue

            visited.add(url)
            response = None

            try:
                response = session.get(
                    url,
                    headers=headers,
                    timeout=TIMEOUT,
                    stream=True,
                )

                response.raise_for_status()

                final_host = urlparse(response.url).hostname

                if final_host != base_host:
                    errors.append("Website redirected outside the target domain.")
                    continue

                if "text/html" not in response.headers.get(
                    "Content-Type", ""
                ).lower():
                    continue

                content = response.raw.read(
                    MAX_PAGE_SIZE + 1,
                    decode_content=True,
                )

                if len(content) > MAX_PAGE_SIZE:
                    errors.append("Website page exceeded the extraction size limit.")
                    continue

                encoding = response.encoding or "utf-8"
                html = content.decode(encoding, errors="replace")

                parser = WebsiteParser()
                parser.feed(html)

                for script in parser.jsonld:
                    try:
                        structured_data = json.loads(script)
                        addresses.extend(
                            collect_addresses(structured_data)
                        )
                    except (ValueError, TypeError):
                        continue

                for link in parser.links:
                    candidate = urljoin(response.url, link)

                    if (
                        urlparse(candidate).hostname == base_host
                        and candidate not in visited
                        and candidate not in urls
                    ):
                        urls.append(candidate)

            except requests.RequestException:
                errors.append("Website page retrieval failed.")

            except (OSError, UnicodeError):
                errors.append("Website page could not be processed.")

            finally:
                if response is not None:
                    response.close()

    published_locations = [
        {
            **normalise_address(address),
            "source": "website structured data",
        }
        for address in addresses
    ]

    return unique(published_locations), errors

def add_related_entity(
    related_entities: list,
    entity_type: str,
    value: str,
    relationship: str,
) -> None:
    if not value:
        return

    related_entities.append({
        "type": entity_type,
        "value": value,
        "relationship": relationship,
    })

def run(domain: str) -> dict:
    data = empty_data()
    provenance = []
    related_entities = []
    errors = []

    successful_sources = 0

    try:
        domain = domain.strip().lower().rstrip(".")

        if not domain:
            raise ValueError("A domain must be provided.")

        try:
            registrant = get_rdap_location(domain)

            if registrant:
                data["registrant_location"] = registrant

            successful_sources += 1

            add_provenance(
                provenance,
                RDAP_ENDPOINT.format(domain),
                "RDAP registrant address extraction",
            )

            if registrant:
                for field in (
                    "country",
                    "region",
                    "city",
                ):
                    add_related_entity(
                        related_entities,
                        "location",
                        registrant.get(field),
                        f"registrant_{field}",
                    )

        except (
            requests.RequestException,
            ValueError,
            TypeError,
            KeyError,
        ):
            errors.append("RDAP location retrieval failed.")

        try:
            addresses = get_ip_addresses(domain)
            data["ip_addresses"] = addresses

            successful_sources += 1

            add_provenance(
                provenance,
                "System DNS resolver",
                "Target domain IP address resolution",
            )

            for address in addresses:
                add_related_entity(
                    related_entities,
                    "ip_address",
                    address,
                    "resolved_from_target_domain",
                )

        except OSError:
            errors.append("Target domain IP resolution failed.")

        try:
            nameservers = get_dns_records(domain, "NS")
            nameserver_ips = set()

            for nameserver in nameservers:
                hostname = nameserver.rstrip(".").lower()

                try:
                    addresses = get_ip_addresses(hostname)
                    nameserver_ips.update(addresses)

                    for address in addresses:
                        add_related_entity(
                            related_entities,
                            "ip_address",
                            address,
                            "nameserver_ip_address",
                        )

                except OSError:
                    errors.append("Nameserver IP resolution failed.")

                add_related_entity(
                    related_entities,
                    "hostname",
                    hostname,
                    "nameserver",
                )

            data["nameserver_ip_addresses"] = sorted(nameserver_ips)

            successful_sources += 1

            add_provenance(
                provenance,
                "Cloudflare DNS",
                "Nameserver record and IP address retrieval",
            )

        except (
            requests.RequestException,
            ValueError,
            TypeError,
        ):
            errors.append("Nameserver retrieval failed.")

        try:
            mail_servers = get_dns_records(domain, "MX")
            mail_server_ips = set()

            for record in mail_servers:
                parts = record.split()

                if not parts:
                    continue

                hostname = parts[-1].rstrip(".").lower()

                try:
                    addresses = get_ip_addresses(hostname)
                    mail_server_ips.update(addresses)

                    for address in addresses:
                        add_related_entity(
                            related_entities,
                            "ip_address",
                            address,
                            "mail_server_ip_address",
                        )

                except OSError:
                    errors.append("Mail server IP resolution failed.")

                add_related_entity(
                    related_entities,
                    "hostname",
                    hostname,
                    "mail_server",
                )

            data["mail_server_ip_addresses"] = sorted(mail_server_ips)

            successful_sources += 1

            add_provenance(
                provenance,
                "Cloudflare DNS",
                "Mail exchanger record and IP address retrieval",
            )

        except (
            requests.RequestException,
            ValueError,
            TypeError,
        ):
            errors.append("Mail server retrieval failed.")

        try:
            published_locations, website_errors = (
                extract_website_addresses(domain)
            )

            data["published_locations"] = published_locations
            errors.extend(website_errors)

            successful_sources += 1

            add_provenance(
                provenance,
                f"https://{domain}",
                "Website JSON-LD structured address extraction",
            )

            for location in published_locations:
                for field in ("country", "region", "city"):
                    add_related_entity(
                        related_entities,
                        "location",
                        location.get(field),
                        f"published_{field}",
                    )

        except (
            requests.RequestException,
            ValueError,
            TypeError,
        ):
            errors.append("Website location extraction failed.")

        related_entities = unique(related_entities)

        populated_fields = any(
            value is not None and value != [] and value != {}
            for value in data.values()
        )

        if errors and populated_fields:
            status = "partial"
        elif errors:
            status = "error"
        elif populated_fields:
            status = "success"
        elif successful_sources:
            status = "no_results"
        else:
            status = "error"

        return make_envelope(
            status=status,
            data=data,
            provenance=provenance,
            related_entities=related_entities,
            errors=errors,
        )

    except Exception:
        return make_envelope(
            status="error",
            data=data,
            provenance=provenance,
            related_entities=related_entities,
            errors=["Geography extraction failed."],
        )