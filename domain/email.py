import io
import re
import zipfile
import xml.etree.ElementTree as ET

import requests

from datetime import datetime, timezone
from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse

RDAP_ENDPOINT = "https://rdap.org/domain/{}"
DNS_ENDPOINT = "https://cloudflare-dns.com/dns-query"

TIMEOUT = 15
MAX_PAGES = 8
MAX_DOCUMENTS = 10
MAX_DOCUMENT_SIZE = 5 * 1024 * 1024

FIELDS = (
    "website_email_addresses",
    "registrant_email_addresses",
    "administrative_contact_emails",
    "technical_contact_emails",
    "abuse_contact_emails",
    "public_document_email_addresses",
    "mail_server_hostnames",
    "spf_related_domains",
    "dkim_selector_names",
    "dmarc_reporting_addresses",
    "email_service_providers",
)

DKIM_SELECTORS = (
    "default",
    "google",
    "googlemail",
    "selector1",
    "selector2",
    "k1",
    "k2",
    "s1",
    "s2",
    "mail",
    "email",
    "smtp",
    "dkim",
    "mandrill",
    "everlytickey1",
    "everlytickey2",
    "amazonses",
    "sendgrid",
    "mailchimp",
    "protonmail",
    "zoho",
    "hs1",
    "hs2",
)

EMAIL_PATTERN = re.compile(
    r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b",
    re.IGNORECASE
)

def empty_data() -> dict:
    return {
        field: []
        for field in FIELDS
    }

def unique(values: list) -> list:
    return sorted({
        value.strip()
        for value in values
        if isinstance(value, str) and value.strip()
    })


def request_json(url: str, params: dict = None) -> dict:
    response = requests.get(
        url,
        params=params,
        headers={"Accept": "application/json"},
        timeout=TIMEOUT
    )

    response.raise_for_status()
    return response.json()

def get_dns_records(name: str, record_type: str) -> list:
    try:
        response = requests.get(
            DNS_ENDPOINT,
            params={
                "name": name,
                "type": record_type
            },
            headers={"Accept": "application/dns-json"},
            timeout=TIMEOUT
        )

        response.raise_for_status()

        result = response.json()

        return [
            record.get("data", "")
            for record in result.get("Answer", [])
            if record.get("data")
        ]

    except (
        requests.RequestException,
        ValueError,
        TypeError
    ):
        return []

def extract_emails(text: str) -> set:
    if not text:
        return set()

    return {
        email.lower()
        for email in EMAIL_PATTERN.findall(text)
    }

def get_rdap_emails(domain: str) -> dict:
    result = {
        "registrant": [],
        "administrative": [],
        "technical": [],
        "abuse": []
    }

    try:
        response = request_json(
            RDAP_ENDPOINT.format(domain)
        )

        for entity in response.get("entities", []):
            roles = entity.get("roles", [])
            emails = set()

            for item in entity.get("vcardArray", [None, []])[1]:
                if (
                    isinstance(item, list)
                    and len(item) >= 4
                    and item[0] == "email"
                ):
                    emails.update(
                        extract_emails(str(item[3]))
                    )

            if not emails:
                continue

            for role in roles:
                if role == "registrant":
                    result["registrant"].update(emails) if isinstance(
                        result["registrant"], set
                    ) else result["registrant"].extend(emails)

                elif role == "administrative":
                    result["administrative"].extend(emails)

                elif role == "technical":
                    result["technical"].extend(emails)

                elif role == "abuse":
                    result["abuse"].extend(emails)

    except (
        requests.RequestException,
        ValueError,
        TypeError,
        KeyError
    ):
        pass

    return {
        key: unique(list(values))
        for key, values in result.items()
    }

class WebsiteParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.text = []
        self.links = []

    def handle_data(self, data):
        self.text.append(data)

    def handle_starttag(self, tag, attrs):
        attributes = dict(attrs)

        if tag == "a":
            href = attributes.get("href")

            if href:
                self.links.append(href)

        elif tag == "mailto":
            href = attributes.get("href")

            if href:
                self.links.append(href)

def crawl_website(domain: str) -> tuple:
    base_url = f"https://{domain}/"

    pages = [
        base_url,
        urljoin(base_url, "contact"),
        urljoin(base_url, "about"),
        urljoin(base_url, "support"),
        urljoin(base_url, "privacy"),
    ]

    visited = set()
    emails = set()
    documents = set()

    while pages and len(visited) < MAX_PAGES:
        url = pages.pop(0)

        if url in visited:
            continue

        visited.add(url)

        try:
            response = requests.get(
                url,
                timeout=TIMEOUT,
                headers={
                    "User-Agent": "Theseus/1.0"
                }
            )

            response.raise_for_status()

            if "text/html" not in response.headers.get(
                "Content-Type", ""
            ):
                continue

            parser = WebsiteParser()
            parser.feed(response.text)

            emails.update(extract_emails(response.text))
            emails.update(extract_emails(" ".join(parser.text)))

            for link in parser.links:
                if link.lower().startswith("mailto:"):
                    emails.update(
                        extract_emails(link)
                    )
                    continue

                absolute_url = urljoin(url, link)
                parsed = urlparse(absolute_url)

                if parsed.scheme not in ("http", "https"):
                    continue

                if parsed.netloc != urlparse(base_url).netloc:
                    continue

                path = parsed.path.lower()

                if path.endswith((".pdf", ".docx")):
                    documents.add(absolute_url)

                elif any(
                    keyword in path
                    for keyword in (
                        "contact",
                        "about",
                        "support",
                        "privacy"
                    )
                ):
                    if absolute_url not in visited:
                        pages.append(absolute_url)

        except requests.RequestException:
            continue

    return emails, sorted(documents)

def extract_pdf_text(content: bytes) -> str:
    try:
        from pypdf import PdfReader

        reader = PdfReader(io.BytesIO(content))

        return "\n".join(
            page.extract_text() or ""
            for page in reader.pages
        )

    except Exception:
        return ""

def extract_docx_text(content: bytes) -> str:
    try:
        with zipfile.ZipFile(io.BytesIO(content)) as archive:
            xml_content = archive.read("word/document.xml")

        root = ET.fromstring(xml_content)

        return " ".join(
            element.text or ""
            for element in root.iter()
            if element.tag.endswith("}t")
        )

    except Exception:
        return ""

def extract_document_emails(url: str) -> list:
    try:
        response = requests.get(
            url,
            timeout=TIMEOUT,
            headers={"User-Agent": "Theseus/1.0"},
            stream=True
        )

        response.raise_for_status()

        content = response.raw.read(
            MAX_DOCUMENT_SIZE + 1
        )

        response.close()

        if len(content) > MAX_DOCUMENT_SIZE:
            return []

        path = urlparse(url).path.lower()

        if path.endswith(".pdf"):
            text = extract_pdf_text(content)

        elif path.endswith(".docx"):
            text = extract_docx_text(content)

        else:
            return []

        return list(extract_emails(text))

    except (
        requests.RequestException,
        ValueError
    ):
        return []

def get_mail_servers(domain: str) -> list:
    records = get_dns_records(domain, "MX")

    hostnames = []

    for record in records:
        parts = record.split()

        if len(parts) >= 2:
            hostname = parts[-1].rstrip(".").lower()

            if hostname:
                hostnames.append(hostname)

    return unique(hostnames)

def get_spf_domains(domain: str) -> list:
    records = get_dns_records(domain, "TXT")

    related_domains = set()

    for record in records:
        record = record.strip('"')

        if not record.lower().startswith("v=spf1"):
            continue

        tokens = record.split()

        for token in tokens:
            token = token.lower()

            if token.startswith("include:"):
                related_domains.add(
                    token.split(":", 1)[1].rstrip(".")
                )

            elif token.startswith("redirect="):
                related_domains.add(
                    token.split("=", 1)[1].rstrip(".")
                )

            elif token.startswith("exists:"):
                related_domains.add(
                    token.split(":", 1)[1].rstrip(".")
                )

            elif token.startswith(("a:", "mx:")):
                related_domains.add(
                    token.split(":", 1)[1].rstrip(".")
                )

    return sorted(related_domains)

def get_dkim_selectors(domain: str) -> list:
    found = []

    for selector in DKIM_SELECTORS:
        record_name = f"{selector}._domainkey.{domain}"

        records = get_dns_records(
            record_name,
            "TXT"
        )

        if any(
            "v=dkim1" in record.lower()
            or "p=" in record.lower()
            for record in records
        ):
            found.append(selector)

    return unique(found)

def get_dmarc_addresses(domain: str) -> list:
    records = get_dns_records(
        f"_dmarc.{domain}",
        "TXT"
    )

    addresses = set()

    for record in records:
        record = record.strip('"')

        if not record.lower().startswith("v=dmarc1"):
            continue

        for tag in ("rua=", "ruf="):
            match = re.search(
                rf"(?:^|;)\s*{tag}([^;]+)",
                record,
                re.IGNORECASE
            )

            if not match:
                continue

            for entry in match.group(1).split(","):
                entry = entry.strip()

                if ":" in entry:
                    entry = entry.split(":", 1)[1]

                addresses.update(
                    extract_emails(entry)
                )

    return sorted(addresses)

def identify_email_providers(
    domain: str,
    mail_servers: list,
    spf_domains: list
) -> list:
    infrastructure = " ".join(
        mail_servers + spf_domains
    ).lower()

    provider_patterns = {
        "Google Workspace": (
            "google.com",
            "googlemail.com",
            "aspmx"
        ),
        "Microsoft 365": (
            "outlook.com",
            "protection.outlook.com",
            "office365.com"
        ),
        "Zoho Mail": (
            "zoho.com",
            "zohomail.com"
        ),
        "Proton Mail": (
            "protonmail.ch",
            "protonmail.com"
        ),
        "Fastmail": (
            "messagingengine.com",
            "fastmail.com"
        ),
        "Amazon SES": (
            "amazonses.com",
        ),
        "SendGrid": (
            "sendgrid.net",
        ),
        "Mailchimp": (
            "mandrillapp.com",
            "mailchimp.com"
        ),
        "Mimecast": (
            "mimecast.com",
        ),
        "Proofpoint": (
            "pphosted.com",
            "proofpoint.com"
        ),
    }

    providers = []

    for provider, patterns in provider_patterns.items():
        if any(
            pattern in infrastructure
            for pattern in patterns
        ):
            providers.append(provider)

    return sorted(set(providers))

def run(domain: str) -> dict:
    data = empty_data()
    provenance = []
    related_entities = []
    errors = []

    try:
        rdap_data = get_rdap_emails(domain)

        data["registrant_email_addresses"] = (
            rdap_data["registrant"]
        )

        data["administrative_contact_emails"] = (
            rdap_data["administrative"]
        )

        data["technical_contact_emails"] = (
            rdap_data["technical"]
        )

        data["abuse_contact_emails"] = (
            rdap_data["abuse"]
        )

        provenance.append({
            "source": RDAP_ENDPOINT.format(domain),
            "method": "RDAP contact extraction",
            "retrieved_at": datetime.now(
                timezone.utc
            ).isoformat()
        })

    except Exception as exc:
        errors.append(f"RDAP retrieval failed: {exc}")

    try:
        website_emails, document_urls = crawl_website(domain)

        data["website_email_addresses"] = sorted(
            website_emails
        )

        document_emails = set()

        for url in document_urls[:MAX_DOCUMENTS]:
            document_emails.update(
                extract_document_emails(url)
            )

        data["public_document_email_addresses"] = sorted(
            document_emails
        )

        provenance.append({
            "source": f"https://{domain}",
            "method": "Website and public document inspection",
            "retrieved_at": datetime.now(
                timezone.utc
            ).isoformat()
        })

    except Exception as exc:
        errors.append(f"Website inspection failed: {exc}")

    try:
        mail_servers = get_mail_servers(domain)
        spf_domains = get_spf_domains(domain)
        dkim_selectors = get_dkim_selectors(domain)
        dmarc_addresses = get_dmarc_addresses(domain)

        data["mail_server_hostnames"] = mail_servers
        data["spf_related_domains"] = spf_domains
        data["dkim_selector_names"] = dkim_selectors
        data["dmarc_reporting_addresses"] = dmarc_addresses

        data["email_service_providers"] = (
            identify_email_providers(
                domain,
                mail_servers,
                spf_domains
            )
        )

        provenance.append({
            "source": DNS_ENDPOINT,
            "method": "DNS MX, TXT and DKIM record inspection",
            "retrieved_at": datetime.now(
                timezone.utc
            ).isoformat()
        })

    except Exception as exc:
        errors.append(f"DNS inspection failed: {exc}")

    all_emails = set()

    for field in (
        "website_email_addresses",
        "registrant_email_addresses",
        "administrative_contact_emails",
        "technical_contact_emails",
        "abuse_contact_emails",
        "public_document_email_addresses",
        "dmarc_reporting_addresses",
    ):
        all_emails.update(data[field])

    related_entities.extend(
        {
            "type": "email_address",
            "value": email,
            "relationship": "publicly_associated_with_domain"
        }
        for email in sorted(all_emails)
    )

    related_entities.extend(
        {
            "type": "hostname",
            "value": hostname,
            "relationship": "mail_server"
        }
        for hostname in data["mail_server_hostnames"]
    )

    related_entities.extend(
        {
            "type": "domain",
            "value": related_domain,
            "relationship": "referenced_in_spf_record"
        }
        for related_domain in data["spf_related_domains"]
    )

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
        "module": "email",
        "data": data,
        "provenance": provenance,
        "related_entities": related_entities
    }

    if errors:
        result["error"] = errors

    return result