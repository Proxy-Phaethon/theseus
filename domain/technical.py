import hashlib
import json
import re
import socket
import ssl
import requests

from datetime import datetime, timezone
from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse

from cryptography import x509
from cryptography.hazmat.primitives import serialization

TIMEOUT = 8
MAX_RESOURCE_SIZE = 5 * 1024 * 1024
MAX_JAVASCRIPT_FILES = 30

DNS_ENDPOINT = "https://cloudflare-dns.com/dns-query"

COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    465: "SMTPS",
    587: "SMTP Submission",
    993: "IMAPS",
    995: "POP3S",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    8080: "HTTP Alternate",
    8443: "HTTPS Alternate",
}

DOCUMENT_EXTENSIONS = (
    ".pdf",
    ".doc",
    ".docx",
    ".xls",
    ".xlsx",
    ".ppt",
    ".pptx",
    ".txt",
    ".csv",
    ".xml",
    ".json",
)

FIELDS = (
    "favicon_hashes",
    "http_response_hashes",
    "html_content_hashes",
    "javascript_file_hashes",
    "public_key_fingerprints",
    "tls_fingerprints",
    "dns_configuration_fingerprints",
    "server_banners",
    "open_ports",
    "service_versions",
    "public_api_endpoints",
    "public_document_urls",
    "sitemap_urls",
    "robots_txt_references",
    "public_source_map_urls",
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
            key = json.dumps(value, sort_keys=True)
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
        key=lambda item: (
            json.dumps(item, sort_keys=True)
            if isinstance(item, dict)
            else str(item).lower()
        )
    )

def sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()

def md5(content: bytes) -> str:
    return hashlib.md5(content).hexdigest()

def request_resource(url: str):
    response = requests.get(
        url,
        timeout=TIMEOUT,
        headers={
            "User-Agent": "Theseus/1.0"
        },
        allow_redirects=True,
        stream=True
    )

    response.raise_for_status()

    content = response.raw.read(
        MAX_RESOURCE_SIZE + 1
    )

    response.close()

    if len(content) > MAX_RESOURCE_SIZE:
        raise ValueError("Resource exceeds maximum size")

    return response, content

def get_domain_hostname(domain: str) -> str:
    return domain.lower().rstrip(".")

def is_same_domain(url: str, domain: str) -> bool:
    hostname = urlparse(url).hostname

    if not hostname:
        return False

    hostname = hostname.lower().rstrip(".")

    return (
        hostname == domain
        or hostname.endswith("." + domain)
    )

class TechnicalParser(HTMLParser):
    def __init__(self):
        super().__init__()

        self.scripts = []
        self.links = []
        self.resources = []
        self.api_candidates = []
        self.inline_scripts = []

        self.in_script = False
        self.script_attributes = {}

    def handle_starttag(self, tag, attrs):
        attributes = dict(attrs)

        if tag == "script":
            self.in_script = True
            self.script_attributes = attributes

            source = attributes.get("src")

            if source:
                self.scripts.append(source)

        if tag == "link":
            href = attributes.get("href")
            rel = attributes.get("rel", "").lower()

            if href:
                self.links.append({
                    "href": href,
                    "rel": rel
                })

                if "icon" in rel:
                    self.resources.append(href)

        if tag in ("img", "iframe", "source"):
            source = (
                attributes.get("src")
                or attributes.get("data-src")
            )

            if source:
                self.resources.append(source)

        for attribute in (
            "href",
            "src",
            "action",
            "data-url",
            "data-api",
        ):
            value = attributes.get(attribute)

            if value:
                self._find_api_candidates(value)

    def handle_data(self, data):
        if self.in_script and data.strip():
            self.inline_scripts.append(data)

    def handle_endtag(self, tag):
        if tag == "script":
            self.in_script = False
            self.script_attributes = {}

    def _find_api_candidates(self, value):
        if re.search(
            r"/(?:api|graphql|rest|v\d+/api)(?:/|$|\?)",
            value,
            re.IGNORECASE
        ):
            self.api_candidates.append(value)

def get_html(domain: str):
    url = f"https://{domain}/"

    try:
        response = requests.get(
            url,
            timeout=TIMEOUT,
            headers={"User-Agent": "Theseus/1.0"},
            allow_redirects=True
        )

        response.raise_for_status()

        return response, response.content

    except requests.RequestException:
        response = requests.get(
            f"http://{domain}/",
            timeout=TIMEOUT,
            headers={"User-Agent": "Theseus/1.0"},
            allow_redirects=True
        )

        response.raise_for_status()

        return response, response.content

def extract_favicon_urls(
    parser: TechnicalParser,
    base_url: str
) -> list:
    favicons = []

    for link in parser.links:
        rel = link.get("rel", "")

        if "icon" in rel:
            favicons.append(
                urljoin(base_url, link["href"])
            )

    if not favicons:
        favicons.append(
            urljoin(base_url, "/favicon.ico")
        )

    return unique(favicons)

def retrieve_favicon_hashes(
    favicon_urls: list,
    data: dict
):
    for url in favicon_urls:
        try:
            _, content = request_resource(url)

            data["favicon_hashes"].append({
                "url": url,
                "md5": md5(content),
                "sha256": sha256(content),
                "size_bytes": len(content)
            })

        except (
            requests.RequestException,
            ValueError
        ):
            continue

def retrieve_javascript_hashes(
    parser: TechnicalParser,
    base_url: str,
    domain: str,
    data: dict
):
    scripts = unique([
        urljoin(base_url, source)
        for source in parser.scripts
    ])

    for url in scripts[:MAX_JAVASCRIPT_FILES]:
        if not is_same_domain(url, domain):
            continue

        try:
            response, content = request_resource(url)

            data["javascript_file_hashes"].append({
                "url": response.url,
                "sha256": sha256(content),
                "size_bytes": len(content)
            })

            source_map_pattern = re.compile(
                r"sourceMappingURL\s*=\s*([^\s*]+)"
            )

            matches = source_map_pattern.findall(
                content.decode("utf-8", errors="ignore")
            )

            for source_map in matches:
                if source_map.startswith("data:"):
                    continue

                map_url = urljoin(
                    response.url,
                    source_map
                )

                data["public_source_map_urls"].append(
                    map_url
                )

        except (
            requests.RequestException,
            ValueError
        ):
            continue

    for script in parser.inline_scripts:
        matches = re.findall(
            r"sourceMappingURL\s*=\s*([^\s*]+)",
            script
        )

        for source_map in matches:
            if not source_map.startswith("data:"):
                data["public_source_map_urls"].append(
                    urljoin(base_url, source_map)
                )

def retrieve_tls_information(domain: str, data: dict):
    context = ssl.create_default_context()

    with socket.create_connection(
        (domain, 443),
        timeout=TIMEOUT
    ) as connection:

        with context.wrap_socket(
            connection,
            server_hostname=domain
        ) as secure_connection:

            certificate_der = secure_connection.getpeercert(
                binary_form=True
            )

            certificate = x509.load_der_x509_certificate(
                certificate_der
            )

            public_key_der = certificate.public_key().public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )

            data["public_key_fingerprints"].append({
                "algorithm": "SHA-256",
                "fingerprint": hashlib.sha256(
                    public_key_der
                ).hexdigest()
            })

            data["tls_fingerprints"].append({
                "certificate_sha256": sha256(certificate_der),
                "protocol": secure_connection.version(),
                "cipher": secure_connection.cipher()[0],
                "cipher_protocol": secure_connection.cipher()[1],
            })

def retrieve_dns_fingerprint(domain: str, data: dict):
    record_types = (
        "A",
        "AAAA",
        "NS",
        "MX",
        "TXT",
        "CNAME",
        "CAA",
    )

    records = {}

    for record_type in record_types:
        try:
            response = requests.get(
                DNS_ENDPOINT,
                params={
                    "name": domain,
                    "type": record_type
                },
                headers={
                    "Accept": "application/dns-json"
                },
                timeout=TIMEOUT
            )

            response.raise_for_status()

            result = response.json()

            records[record_type] = sorted(
                record.get("data", "")
                for record in result.get("Answer", [])
            )

        except (
            requests.RequestException,
            ValueError
        ):
            records[record_type] = []

    fingerprint_input = json.dumps(
        records,
        sort_keys=True
    ).encode("utf-8")

    data["dns_configuration_fingerprints"].append({
        "algorithm": "SHA-256",
        "fingerprint": sha256(fingerprint_input),
        "record_sets": records
    })

def retrieve_server_information(
    response,
    data: dict
):
    data["http_response_hashes"].append({
        "url": response.url,
        "sha256": sha256(response.content),
        "size_bytes": len(response.content),
        "status_code": response.status_code
    })

    headers = response.headers

    server = headers.get("Server")

    if server:
        data["server_banners"].append({
            "type": "HTTP Server",
            "value": server
        })

        version_match = re.search(
            r"([A-Za-z_-]+)/([\d.]+)",
            server
        )

        if version_match:
            data["service_versions"].append({
                "service": version_match.group(1),
                "version": version_match.group(2)
            })

    for header in (
        "X-Powered-By",
        "X-AspNet-Version",
        "X-Generator",
        "Via",
    ):
        value = headers.get(header)

        if value:
            data["server_banners"].append({
                "type": header,
                "value": value
            })

def retrieve_open_ports(domain: str, data: dict):
    try:
        addresses = socket.getaddrinfo(
            domain,
            None,
            type=socket.SOCK_STREAM
        )

    except socket.gaierror:
        return

    ip_addresses = sorted({
        address[4][0]
        for address in addresses
    })

    for ip_address in ip_addresses:
        for port, service in COMMON_PORTS.items():
            try:
                with socket.create_connection(
                    (ip_address, port),
                    timeout=2
                ):
                    data["open_ports"].append({
                        "ip_address": ip_address,
                        "port": port,
                        "service": service,
                        "protocol": "TCP"
                    })

            except (
                OSError,
                socket.timeout
            ):
                continue

def retrieve_service_versions(domain: str, data: dict):
    for item in data["open_ports"]:
        port = item["port"]
        service = item["service"]

        if port not in (21, 22, 25, 110, 143):
            continue

        try:
            with socket.create_connection(
                (item["ip_address"], port),
                timeout=TIMEOUT
            ) as connection:

                connection.settimeout(3)

                try:
                    banner = connection.recv(1024).decode(
                        "utf-8",
                        errors="replace"
                    ).strip()

                except socket.timeout:
                    banner = ""

                if banner:
                    data["server_banners"].append({
                        "type": "TCP service banner",
                        "service": service,
                        "port": port,
                        "value": banner
                    })

                    version = re.search(
                        r"\b(\d+(?:\.\d+){1,3})\b",
                        banner
                    )

                    if version:
                        data["service_versions"].append({
                            "service": service,
                            "version": version.group(1),
                            "port": port
                        })

        except OSError:
            continue

def retrieve_public_resources(
    parser: TechnicalParser,
    base_url: str,
    domain: str,
    data: dict
):
    candidates = set(parser.api_candidates)

    for source in parser.scripts:
        if source.startswith("data:"):
            continue

        url = urljoin(base_url, source)

        if not is_same_domain(url, domain):
            continue

        try:
            _, content = request_resource(url)

            text = content.decode(
                "utf-8",
                errors="ignore"
            )

            patterns = (
                r"""["']((?:https?://[^"' ]+)?/(?:api|graphql|rest|v\d+/api)[^"' ]*)["']""",
                r"""["']((?:https?://[^"' ]+)?/api/[^"' ]*)["']""",
            )

            for pattern in patterns:
                for match in re.findall(pattern, text):
                    candidates.add(match)

        except (
            requests.RequestException,
            ValueError
        ):
            continue

    for candidate in candidates:
        endpoint = urljoin(base_url, candidate)

        if is_same_domain(endpoint, domain):
            data["public_api_endpoints"].append(endpoint)

    for link in parser.links:
        url = urljoin(base_url, link["href"])

        path = urlparse(url).path.lower()

        if path.endswith(DOCUMENT_EXTENSIONS):
            data["public_document_urls"].append(url)

def retrieve_sitemaps_and_robots(
    base_url: str,
    domain: str,
    data: dict
):
    robots_url = urljoin(base_url, "/robots.txt")

    try:
        response = requests.get(
            robots_url,
            timeout=TIMEOUT,
            headers={"User-Agent": "Theseus/1.0"}
        )

        if response.status_code == 200:
            for line in response.text.splitlines():
                line = line.strip()

                if not line or line.startswith("#"):
                    continue

                data["robots_txt_references"].append(line)

                if line.lower().startswith("sitemap:"):
                    sitemap = line.split(":", 1)[1].strip()

                    if sitemap:
                        data["sitemap_urls"].append(
                            urljoin(base_url, sitemap)
                        )

    except requests.RequestException:
        pass

    conventional_sitemap = urljoin(
        base_url,
        "/sitemap.xml"
    )

    if conventional_sitemap not in data["sitemap_urls"]:
        data["sitemap_urls"].append(
            conventional_sitemap
        )

def run(domain: str) -> dict:
    data = empty_data()
    provenance = []
    related_entities = []
    errors = []

    domain = get_domain_hostname(domain)
    base_url = f"https://{domain}/"

    parser = None
    response = None

    try:
        response, html_content = get_html(domain)

        data["html_content_hashes"].append({
            "url": response.url,
            "sha256": sha256(html_content),
            "size_bytes": len(html_content)
        })

        parser = TechnicalParser()
        parser.feed(html_content.decode(
            response.encoding or "utf-8",
            errors="replace"
        ))

        retrieve_server_information(
            response,
            data
        )

        base_url = response.url

        provenance.append({
            "source": base_url,
            "method": "HTTP response and HTML inspection",
            "retrieved_at": datetime.now(
                timezone.utc
            ).isoformat()
        })

    except (
        requests.RequestException,
        ValueError,
        UnicodeError
    ) as exc:
        errors.append(
            f"Website retrieval failed: {exc}"
        )

    if parser is not None:
        try:
            favicon_urls = extract_favicon_urls(
                parser,
                base_url
            )

            retrieve_favicon_hashes(
                favicon_urls,
                data
            )

        except Exception as exc:
            errors.append(
                f"Favicon retrieval failed: {exc}"
            )

        try:
            retrieve_javascript_hashes(
                parser,
                base_url,
                domain,
                data
            )

        except Exception as exc:
            errors.append(
                f"JavaScript inspection failed: {exc}"
            )

        try:
            retrieve_public_resources(
                parser,
                base_url,
                domain,
                data
            )

        except Exception as exc:
            errors.append(
                f"Public resource discovery failed: {exc}"
            )

    try:
        retrieve_tls_information(
            domain,
            data
        )

        provenance.append({
            "source": f"https://{domain}:443",
            "method": "TLS certificate and connection inspection",
            "retrieved_at": datetime.now(
                timezone.utc
            ).isoformat()
        })

    except Exception as exc:
        errors.append(
            f"TLS inspection failed: {exc}"
        )

    try:
        retrieve_dns_fingerprint(
            domain,
            data
        )

        provenance.append({
            "source": DNS_ENDPOINT,
            "method": "DNS record set fingerprinting",
            "retrieved_at": datetime.now(
                timezone.utc
            ).isoformat()
        })

    except Exception as exc:
        errors.append(
            f"DNS fingerprinting failed: {exc}"
        )

    try:
        retrieve_open_ports(
            domain,
            data
        )

        retrieve_service_versions(
            domain,
            data
        )

        provenance.append({
            "source": domain,
            "method": "Limited TCP connectivity checks",
            "retrieved_at": datetime.now(
                timezone.utc
            ).isoformat()
        })

    except Exception as exc:
        errors.append(
            f"Port inspection failed: {exc}"
        )

    try:
        retrieve_sitemaps_and_robots(
            base_url,
            domain,
            data
        )

        provenance.append({
            "source": base_url,
            "method": "Sitemap and robots.txt inspection",
            "retrieved_at": datetime.now(
                timezone.utc
            ).isoformat()
        })

    except Exception as exc:
        errors.append(
            f"Sitemap and robots inspection failed: {exc}"
        )

    for field in FIELDS:
        data[field] = unique(data[field])

    for item in data["open_ports"]:
        related_entities.append({
            "type": "service",
            "value": f"{item['service']}:{item['port']}",
            "relationship": "exposed_on_domain_infrastructure"
        })

    for endpoint in data["public_api_endpoints"]:
        related_entities.append({
            "type": "url",
            "value": endpoint,
            "relationship": "public_api_endpoint"
        })

    for url in data["public_document_urls"]:
        related_entities.append({
            "type": "url",
            "value": url,
            "relationship": "public_document"
        })

    for hostname in data["sitemap_urls"]:
        related_entities.append({
            "type": "url",
            "value": hostname,
            "relationship": "sitemap_resource"
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
        "module": "technical",
        "data": data,
        "provenance": provenance,
        "related_entities": related_entities
    }

    if errors:
        result["error"] = errors

    return result