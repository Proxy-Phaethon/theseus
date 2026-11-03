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

MODULE_NAME = "email"

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
    re.IGNORECASE,
)

def empty_data() -> dict:
    return {field: [] for field in FIELDS}

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

def timestamp() -> str:
    return datetime.now(timezone.utc).isoformat()

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
        timeout=TIMEOUT,
    )

    response.raise_for_status()
    return response.json()

def get_dns_records(name: str, record_type: str) -> list:
    response = requests.get(
        DNS_ENDPOINT,
        params={
            "name": name,
            "type": record_type,
        },
        headers={"Accept": "application/dns-json"},
        timeout=TIMEOUT,
    )

    response.raise_for_status()
    result = response.json()

    return [
        record.get("data", "")
        for record in result.get("Answer", [])
        if record.get("data")
    ]

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
        "abuse": [],
    }

    response = request_json(
        RDAP_ENDPOINT.format(domain)
    )

    for entity in response.get("entities", []):
        roles = entity.get("roles", [])
        emails = set()

        vcard = entity.get("vcardArray", [])

        if (
            isinstance(vcard, list)
            and len(vcard) > 1
            and isinstance(vcard[1], list)
        ):
            for item in vcard[1]:
                if (
                    isinstance(item, list)
                    and len(item) >= 4
                    and item[0] == "email"
                ):
                    emails.update(
                        extract_emails(str(item[3]))
                    )

        for role in roles:
            if role in result:
                result[role].extend(emails)

    return {
        key: unique(values)
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

def crawl_website(domain: str) -> tuple[set, list, list]:
    base_url = f"https://{domain}/"
    base_host = urlparse(base_url).netloc

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
    errors = []

    while pages and len(visited) < MAX_PAGES:
        url = pages.pop(0)

        if url in visited:
            continue

        visited.add(url)

        try:
            response = requests.get(
                url,
                timeout=TIMEOUT,
                headers={"User-Agent": "Theseus/1.0"},
                allow_redirects=True,
            )

            response.raise_for_status()

            if urlparse(response.url).netloc != base_host:
                continue

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
                    emails.update(extract_emails(link))
                    continue

                absolute_url = urljoin(response.url, link)
                parsed = urlparse(absolute_url)

                if parsed.scheme not in ("http", "https"):
                    continue

                if parsed.netloc != base_host:
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
                        "privacy",
                    )
                ):
                    if absolute_url not in visited:
                        pages.append(absolute_url)

        except requests.RequestException as exc:
            errors.append(
                f"Website page retrieval failed ({url}): {exc}"
            )

    return emails, sorted(documents), errors

def extract_pdf_text(content: bytes) -> str:
    from pypdf import PdfReader

    reader = PdfReader(io.BytesIO(content))

    return "\n".join(
        page.extract_text() or ""
        for page in reader.pages
    )

def extract_docx_text(content: bytes) -> str:
    with zipfile.ZipFile(io.BytesIO(content)) as archive:
        xml_content = archive.read("word/document.xml")

    root = ET.fromstring(xml_content)

    return " ".join(
        element.text or ""
        for element in root.iter()
        if element.tag.endswith("}t")
    )

def extract_document_emails(url: str) -> list:
    response = requests.get(
        url,
        timeout=TIMEOUT,
        headers={"User-Agent": "Theseus/1.0"},
        stream=True,
    )

    try:
        response.raise_for_status()

        content = response.raw.read(
            MAX_DOCUMENT_SIZE + 1
        )

        if len(content) > MAX_DOCUMENT_SIZE:
            raise ValueError(
                "Document exceeds the maximum permitted size."
            )

        path = urlparse(url).path.lower()

        if path.endswith(".pdf"):
            text = extract_pdf_text(content)

        elif path.endswith(".docx"):
            text = extract_docx_text(content)

        else:
            return []

        return sorted(extract_emails(text))

    finally:
        response.close()

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

        for token in record.split():
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
            "TXT",
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
        "TXT",
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
                re.IGNORECASE,
            )

            if not match:
                continue

            for entry in match.group(1).split(","):
                entry = entry.strip()

                if ":" in entry:
                    entry = entry.split(":", 1)[1]

                addresses.update(extract_emails(entry))

    return sorted(addresses)

def identify_email_providers(
    domain: str,
    mail_servers: list,
    spf_domains: list,
) -> list:
    infrastructure = " ".join(
        mail_servers + spf_domains
    ).lower()

    provider_patterns = {
        "Google Workspace": (
            "google.com",
            "googlemail.com",
            "aspmx",
        ),
        "Microsoft 365": (
            "outlook.com",
            "protection.outlook.com",
            "office365.com",
        ),
        "Zoho Mail": (
            "zoho.com",
            "zohomail.com",
        ),
        "Proton Mail": (
            "protonmail.ch",
            "protonmail.com",
        ),
        "Fastmail": (
            "messagingengine.com",
            "fastmail.com",
        ),
        "Amazon SES": (
            "amazonses.com",
        ),
        "SendGrid": (
            "sendgrid.net",
        ),
        "Mailchimp": (
            "mandrillapp.com",
            "mailchimp.com",
        ),
        "Mimecast": (
            "mimecast.com",
        ),
        "Proofpoint": (
            "pphosted.com",
            "proofpoint.com",
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

    try:
        rdap_data = get_rdap_emails(domain)

        data["registrant_email_addresses"] = rdap_data["registrant"]
        data["administrative_contact_emails"] = rdap_data["administrative"]
        data["technical_contact_emails"] = rdap_data["technical"]
        data["abuse_contact_emails"] = rdap_data["abuse"]

        provenance.append({
            "source": RDAP_ENDPOINT.format(domain),
            "method": "RDAP contact extraction",
            "retrieved_at": timestamp(),
        })

        successful_sources += 1

    except Exception as exc:
        errors.append(f"RDAP retrieval failed: {exc}")

    try:
        website_emails, document_urls, crawl_errors = (
            crawl_website(domain)
        )

        errors.extend(crawl_errors)

        data["website_email_addresses"] = sorted(
            website_emails
        )

        document_emails = set()
        document_errors = []

        for url in document_urls[:MAX_DOCUMENTS]:
            try:
                document_emails.update(
                    extract_document_emails(url)
                )

            except Exception as exc:
                document_errors.append(
                    f"Document extraction failed ({url}): {exc}"
                )

        errors.extend(document_errors)

        data["public_document_email_addresses"] = sorted(
            document_emails
        )

        provenance.append({
            "source": f"https://{domain}",
            "method": "Website and public document inspection",
            "retrieved_at": timestamp(),
        })

        successful_sources += 1

    except Exception as exc:
        errors.append(f"Website inspection failed: {exc}")

    try:
        mail_servers = get_mail_servers(domain)
        data["mail_server_hostnames"] = mail_servers

        provenance.append({
            "source": DNS_ENDPOINT,
            "method": "DNS MX record inspection",
            "retrieved_at": timestamp(),
        })

        successful_sources += 1

    except Exception as exc:
        errors.append(f"MX record retrieval failed: {exc}")
        mail_servers = []

    try:
        spf_domains = get_spf_domains(domain)
        data["spf_related_domains"] = spf_domains

        provenance.append({
            "source": DNS_ENDPOINT,
            "method": "DNS SPF record inspection",
            "retrieved_at": timestamp(),
        })

        successful_sources += 1

    except Exception as exc:
        errors.append(f"SPF record retrieval failed: {exc}")
        spf_domains = []

    try:
        dkim_selectors = get_dkim_selectors(domain)
        data["dkim_selector_names"] = dkim_selectors

        provenance.append({
            "source": DNS_ENDPOINT,
            "method": "DNS DKIM selector inspection",
            "retrieved_at": timestamp(),
        })

        successful_sources += 1

    except Exception as exc:
        errors.append(f"DKIM record retrieval failed: {exc}")

    try:
        dmarc_addresses = get_dmarc_addresses(domain)
        data["dmarc_reporting_addresses"] = dmarc_addresses

        provenance.append({
            "source": DNS_ENDPOINT,
            "method": "DNS DMARC record inspection",
            "retrieved_at": timestamp(),
        })

        successful_sources += 1

    except Exception as exc:
        errors.append(f"DMARC record retrieval failed: {exc}")

    data["email_service_providers"] = identify_email_providers(
        domain,
        mail_servers,
        spf_domains,
    )

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
            "relationship": "observed_in_public_source",
        }
        for email in sorted(all_emails)
    )

    related_entities.extend(
        {
            "type": "hostname",
            "value": hostname,
            "relationship": "mail_server",
        }
        for hostname in data["mail_server_hostnames"]
    )

    related_entities.extend(
        {
            "type": "domain",
            "value": related_domain,
            "relationship": "referenced_in_spf_record",
        }
        for related_domain in data["spf_related_domains"]
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

    return make_envelope(
        data=data,
        status=status,
        provenance=provenance,
        related_entities=related_entities,
        errors=errors,
    )