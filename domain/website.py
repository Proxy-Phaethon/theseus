import json
import re
import requests

from datetime import datetime, timezone
from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse

MODULE_NAME = "website"

TIMEOUT = 15
MAX_PAGES = 10
MAX_PAGE_SIZE = 5 * 1024 * 1024

USER_AGENT = "Theseus/1.0"

SOCIAL_PLATFORMS = {
    "facebook.com": "Facebook",
    "instagram.com": "Instagram",
    "linkedin.com": "LinkedIn",
    "twitter.com": "X",
    "x.com": "X",
    "youtube.com": "YouTube",
    "youtu.be": "YouTube",
    "tiktok.com": "TikTok",
    "github.com": "GitHub",
    "reddit.com": "Reddit",
    "pinterest.com": "Pinterest",
    "threads.net": "Threads",
    "mastodon.social": "Mastodon",
}

SERVICE_DOMAINS = {
    "google-analytics.com": "Google Analytics",
    "googletagmanager.com": "Google Tag Manager",
    "doubleclick.net": "Google Advertising",
    "facebook.net": "Meta",
    "connect.facebook.net": "Meta",
    "hotjar.com": "Hotjar",
    "clarity.ms": "Microsoft Clarity",
    "segment.io": "Segment",
    "segment.com": "Segment",
    "mixpanel.com": "Mixpanel",
    "amplitude.com": "Amplitude",
    "sentry.io": "Sentry",
    "intercom.io": "Intercom",
    "intercomcdn.com": "Intercom",
    "crisp.chat": "Crisp",
    "zendesk.com": "Zendesk",
    "stripe.com": "Stripe",
    "paypal.com": "PayPal",
    "paypalobjects.com": "PayPal",
    "razorpay.com": "Razorpay",
    "razorpay.in": "Razorpay",
    "checkout.com": "Checkout.com",
    "adyen.com": "Adyen",
    "shopify.com": "Shopify",
    "cloudflare.com": "Cloudflare",
    "jsdelivr.net": "jsDelivr",
    "unpkg.com": "unpkg",
    "fontawesome.com": "Font Awesome",
    "fonts.googleapis.com": "Google Fonts",
    "fonts.gstatic.com": "Google Fonts",
}

FIELDS = (
    "company_names",
    "organisation_names",
    "published_individual_names",
    "business_addresses",
    "telephone_numbers",
    "contact_email_addresses",
    "social_media_accounts",
    "public_usernames",
    "legal_entity_identifiers",
    "copyright_holder_names",
    "website_author_names",
    "cms_identifiers",
    "technology_identifiers",
    "analytics_identifiers",
    "advertising_identifiers",
    "payment_provider_identifiers",
    "external_service_domains",
)

EMAIL_PATTERN = re.compile(
    r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b",
    re.IGNORECASE,
)

PHONE_PATTERN = re.compile(
    r"(?<!\w)(?:\+?\d[\d\s()./-]{6,}\d)(?!\w)"
)

LEI_PATTERN = re.compile(
    r"\b[A-Z0-9]{20}\b"
)

ANALYTICS_PATTERNS = {
    "Google Analytics": re.compile(
        r"\b(G-[A-Z0-9]{6,})\b"
    ),
    "Google Universal Analytics": re.compile(
        r"\b(UA-\d{4,}-\d+)\b"
    ),
    "Google Tag Manager": re.compile(
        r"\b(GTM-[A-Z0-9]+)\b"
    ),
    "Microsoft Clarity": re.compile(
        r"clarity\.ms/tag/([a-z0-9]+)",
        re.IGNORECASE,
    ),
}

PAYMENT_PATTERNS = {
    "Stripe": re.compile(
        r"\b(pk_(?:live|test)_[A-Za-z0-9]+)\b"
    ),
    "PayPal": re.compile(
        r"(?:client-id|client_id)=([A-Za-z0-9_-]+)"
    ),
}

def empty_data() -> dict:
    return {field: [] for field in FIELDS}

def timestamp() -> str:
    return datetime.now(timezone.utc).isoformat()

def make_envelope(
    status: str,
    data: dict,
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

def unique(values: list) -> list:
    result = []
    seen = set()

    for value in values:
        if isinstance(value, str):
            value = value.strip()

            if not value:
                continue

            key = value.lower()

        elif isinstance(value, dict):
            key = json.dumps(value, sort_keys=True)

        else:
            continue

        if key not in seen:
            seen.add(key)
            result.append(value)

    return sorted(
        result,
        key=lambda item: (
            json.dumps(item, sort_keys=True)
            if isinstance(item, dict)
            else item.lower()
        ),
    )

def get_domain(hostname: str) -> str:
    parsed = urlparse(
        hostname if "://" in hostname else f"//{hostname}"
    )

    return (parsed.hostname or "").lower().rstrip(".")

def is_http_url(url: str) -> bool:
    return urlparse(url).scheme.lower() in ("http", "https")

def is_internal_url(url: str, domain: str) -> bool:
    hostname = get_domain(url)

    if not hostname:
        return False

    return (
        hostname == domain
        or hostname.endswith("." + domain)
    )

class WebsiteParser(HTMLParser):

    def __init__(self):
        super().__init__()

        self.text = []
        self.links = []
        self.resources = []
        self.metadata = []
        self.json_ld = []

        self.in_script = False
        self.script_type = ""
        self.current_link = None

    def handle_starttag(self, tag, attrs):
        attributes = dict(attrs)

        if tag == "a":
            href = attributes.get("href")

            if href:
                link = {
                    "href": href,
                    "text": "",
                }

                self.links.append(link)
                self.current_link = link

        if tag in ("script", "iframe", "img", "link"):
            source = (
                attributes.get("src")
                or attributes.get("href")
            )

            if source:
                self.resources.append(source)

        if tag == "meta":
            key = (
                attributes.get("property")
                or attributes.get("name")
                or attributes.get("itemprop")
            )

            value = attributes.get("content")

            if key and value:
                self.metadata.append({
                    "key": key.lower(),
                    "value": value.strip(),
                })

        if tag == "script":
            self.in_script = True
            self.script_type = attributes.get("type", "").lower()

    def handle_data(self, data):
        if self.in_script:
            if self.script_type == "application/ld+json":
                self.json_ld.append(data)

        elif data.strip():
            self.text.append(data.strip())

            if self.current_link is not None:
                self.current_link["text"] += data.strip() + " "

    def handle_endtag(self, tag):
        if tag == "script":
            self.in_script = False
            self.script_type = ""

        elif tag == "a":
            self.current_link = None

def get_page(url: str, domain: str):
    if not is_http_url(url):
        raise ValueError("Only HTTP and HTTPS URLs are supported.")

    response = requests.get(
        url,
        timeout=TIMEOUT,
        headers={"User-Agent": USER_AGENT},
        allow_redirects=True,
        stream=True,
    )

    try:
        response.raise_for_status()

        if not is_internal_url(response.url, domain):
            raise ValueError(
                "Page redirected outside the target domain."
            )

        content_type = response.headers.get(
            "Content-Type", ""
        ).lower()

        if "text/html" not in content_type:
            return None, response.url

        content = response.raw.read(MAX_PAGE_SIZE + 1)

        if len(content) > MAX_PAGE_SIZE:
            raise ValueError("HTML page exceeds maximum size.")

        encoding = response.encoding or "utf-8"

        parser = WebsiteParser()
        parser.feed(
            content.decode(
                encoding,
                errors="replace",
            )
        )

        return parser, response.url

    finally:
        response.close()

def extract_jsonld(parser: WebsiteParser) -> list:
    results = []

    for raw in parser.json_ld:
        try:
            value = json.loads(raw)

            if isinstance(value, list):
                results.extend(value)
            else:
                results.append(value)

        except (json.JSONDecodeError, TypeError):
            continue

    return results

def walk_jsonld(value):
    if isinstance(value, dict):
        yield value

        for child in value.values():
            yield from walk_jsonld(child)

    elif isinstance(value, list):
        for child in value:
            yield from walk_jsonld(child)

def normalise_schema_type(value: str) -> str:
    return value.rstrip("/").rsplit("/", 1)[-1].rsplit("#", 1)[-1].lower()

def extract_schema_data(objects: list, data: dict) -> None:
    organisation_types = {
        "organization",
        "corporation",
        "localbusiness",
        "company",
    }

    for root in objects:
        for item in walk_jsonld(root):
            item_type = item.get("@type", [])

            if isinstance(item_type, str):
                item_type = [item_type]

            types = {
                normalise_schema_type(value)
                for value in item_type
                if isinstance(value, str)
            }

            name = item.get("name")

            if isinstance(name, str):
                if types.intersection(organisation_types):
                    data["company_names"].append(name)
                    data["organisation_names"].append(name)

                elif "person" in types:
                    data["published_individual_names"].append(name)

            author = item.get("author")

            if isinstance(author, dict):
                author = author.get("name")

            if isinstance(author, str):
                data["website_author_names"].append(author)

            copyright_holder = item.get("copyrightHolder")

            if isinstance(copyright_holder, dict):
                copyright_holder = copyright_holder.get("name")

            if isinstance(copyright_holder, str):
                data["copyright_holder_names"].append(copyright_holder)

            email = item.get("email")

            if isinstance(email, str):
                data["contact_email_addresses"].extend(
                    EMAIL_PATTERN.findall(email)
                )

            telephone = item.get("telephone")

            if isinstance(telephone, str):
                data["telephone_numbers"].append(telephone)

            address = item.get("address")

            if isinstance(address, dict):
                address_data = {
                    key: address[key]
                    for key in (
                        "streetAddress",
                        "addressLocality",
                        "addressRegion",
                        "postalCode",
                        "addressCountry",
                    )
                    if address.get(key)
                }

                if address_data:
                    data["business_addresses"].append(address_data)

            elif isinstance(address, str):
                data["business_addresses"].append(address)

            identifier = item.get("identifier")

            if isinstance(identifier, dict):
                identifier = identifier.get("value")

            elif isinstance(identifier, list):
                identifier = [
                    entry.get("value")
                    if isinstance(entry, dict)
                    else entry
                    for entry in identifier
                ]

            if isinstance(identifier, str):
                data["legal_entity_identifiers"].append(identifier)

            elif isinstance(identifier, list):
                data["legal_entity_identifiers"].extend(
                    value for value in identifier
                    if isinstance(value, str)
                )

def identify_social_accounts(urls: list, data: dict) -> None:
    for url in urls:
        parsed = urlparse(url)
        hostname = get_domain(url)

        if not hostname:
            continue

        platform = None

        for social_domain, name in SOCIAL_PLATFORMS.items():
            if (
                hostname == social_domain
                or hostname.endswith("." + social_domain)
            ):
                platform = name
                break

        if not platform:
            continue

        path_parts = [
            part for part in parsed.path.split("/")
            if part
        ]

        if not path_parts:
            continue

        username = path_parts[0].lstrip("@")

        data["social_media_accounts"].append({
            "platform": platform,
            "url": url,
        })

        if username:
            data["public_usernames"].append({
                "platform": platform,
                "username": username,
                "url": url,
            })

def identify_services(
    urls: list,
    domain: str,
    data: dict,
) -> None:
    for url in urls:
        hostname = get_domain(url)

        if not hostname or is_internal_url(url, domain):
            continue

        data["external_service_domains"].append(hostname)

        for service_domain, provider in SERVICE_DOMAINS.items():
            if (
                hostname == service_domain
                or hostname.endswith("." + service_domain)
            ):
                data["technology_identifiers"].append(provider)

                if provider in (
                    "Google Analytics",
                    "Google Tag Manager",
                    "Hotjar",
                    "Microsoft Clarity",
                    "Segment",
                    "Mixpanel",
                    "Amplitude",
                ):
                    data["analytics_identifiers"].append(provider)

                if provider in (
                    "Google Advertising",
                    "Meta",
                ):
                    data["advertising_identifiers"].append(provider)

                if provider in (
                    "Stripe",
                    "PayPal",
                    "Razorpay",
                    "Checkout.com",
                    "Adyen",
                ):
                    data["payment_provider_identifiers"].append(provider)

def extract_identifiers(text: str, data: dict) -> None:
    for provider, pattern in ANALYTICS_PATTERNS.items():
        for identifier in pattern.findall(text):
            data["analytics_identifiers"].append({
                "provider": provider,
                "identifier": identifier,
            })

    for provider, pattern in PAYMENT_PATTERNS.items():
        for identifier in pattern.findall(text):
            data["payment_provider_identifiers"].append({
                "provider": provider,
                "identifier": identifier,
            })

def extract_legal_identifiers(text: str, data: dict) -> None:
    for match in LEI_PATTERN.findall(text.upper()):
        data["legal_entity_identifiers"].append({
            "type": "potential_lei",
            "value": match,
        })

def extract_metadata(
    parser: WebsiteParser,
    data: dict,
) -> None:
    for item in parser.metadata:
        key = item["key"]
        value = item["value"]

        if key in ("author", "article:author"):
            data["website_author_names"].append(value)

        elif key == "generator":
            data["cms_identifiers"].append(value)

        elif key in ("og:site_name", "application-name"):
            data["company_names"].append(value)

def identify_cms_and_technologies(
    resources: list,
    source: str,
    data: dict,
) -> None:
    source_lower = source.lower()
    resources_lower = " ".join(resources).lower()

    fingerprints = {
        "WordPress": (
            "wp-content/",
            "wp-includes/",
        ),
        "Drupal": (
            "drupalsettings",
            "/sites/default/files/",
        ),
        "Joomla": (
            "/media/system/js/",
            "joomla!",
        ),
        "Shopify": (
            "cdn.shopify.com",
            "shopify.theme",
        ),
        "Wix": (
            "wixstatic.com",
            "wix.com",
        ),
        "Squarespace": (
            "static.squarespace.com",
            "squarespace.com",
        ),
        "Webflow": (
            "webflow.js",
            "webflow.com",
        ),
        "Next.js": (
            "/_next/",
            "__next_data__",
        ),
        "Nuxt": (
            "/_nuxt/",
            "__nuxt",
        ),
    }

    combined = source_lower + " " + resources_lower

    for technology, patterns in fingerprints.items():
        if any(pattern in combined for pattern in patterns):
            if technology in (
                "WordPress",
                "Drupal",
                "Joomla",
                "Shopify",
                "Wix",
                "Squarespace",
                "Webflow",
            ):
                data["cms_identifiers"].append(technology)

            else:
                data["technology_identifiers"].append(technology)

def run(domain: str) -> dict:
    data = empty_data()
    provenance = []
    related_entities = []
    errors = []

    domain = get_domain(domain)

    if not domain:
        return make_envelope(
            "error",
            data,
            provenance,
            related_entities,
            ["No valid domain was provided."],
        )

    base_url = f"https://{domain}/"

    pages = [
        base_url,
        urljoin(base_url, "about"),
        urljoin(base_url, "contact"),
        urljoin(base_url, "company"),
        urljoin(base_url, "privacy"),
        urljoin(base_url, "terms"),
    ]

    visited = set()
    all_links = set()
    all_resources = set()
    all_source = []

    while pages and len(visited) < MAX_PAGES:
        url = pages.pop(0)

        if url in visited:
            continue

        if not is_internal_url(url, domain):
            continue

        visited.add(url)

        try:
            parser, final_url = get_page(url, domain)

            if parser is None:
                continue

            all_links.update(
                urljoin(final_url, link["href"])
                for link in parser.links
                if link.get("href")
            )

            all_resources.update(
                urljoin(final_url, resource)
                for resource in parser.resources
                if is_http_url(urljoin(final_url, resource))
            )

            page_text = " ".join(parser.text)

            metadata_text = " ".join(
                f"{item['key']} {item['value']}"
                for item in parser.metadata
            )

            source_text = page_text + " " + metadata_text
            all_source.append(source_text)

            data["contact_email_addresses"].extend(
                EMAIL_PATTERN.findall(source_text)
            )

            data["telephone_numbers"].extend(
                PHONE_PATTERN.findall(source_text)
            )

            extract_metadata(parser, data)

            schema_objects = extract_jsonld(parser)
            extract_schema_data(schema_objects, data)

            identify_cms_and_technologies(
                parser.resources,
                source_text,
                data,
            )

            add_provenance(
                provenance,
                final_url,
                "Website HTML and metadata extraction",
            )

            for link in parser.links:
                target = urljoin(final_url, link["href"])
                path = urlparse(target).path.lower()

                if (
                    is_http_url(target)
                    and is_internal_url(target, domain)
                    and any(
                        keyword in path
                        for keyword in (
                            "about",
                            "contact",
                            "company",
                            "team",
                            "legal",
                            "privacy",
                            "terms",
                        )
                    )
                    and target not in visited
                    and target not in pages
                ):
                    pages.append(target)

        except (
            requests.RequestException,
            ValueError,
            UnicodeError,
        ) as exc:
            errors.append(f"Page retrieval failed for {url}: {exc}")

        except Exception as exc:
            errors.append(f"Page extraction failed for {url}: {exc}")

    identify_social_accounts(
        list(all_links),
        data,
    )

    identify_services(
        list(all_resources),
        domain,
        data,
    )

    combined_source = " ".join(all_source)

    extract_identifiers(
        combined_source,
        data,
    )

    extract_legal_identifiers(
        combined_source,
        data,
    )

    copyright_pattern = re.compile(
        r"(?:©|copyright)\s*"
        r"(?:\d{4}(?:\s*[-–]\s*\d{4})?)?"
        r"\s*([^|<>\n]+)",
        re.IGNORECASE,
    )

    for match in copyright_pattern.findall(combined_source):
        holder = match.strip(" .,-")

        if holder:
            data["copyright_holder_names"].append(holder)

    for field in FIELDS:
        data[field] = unique(data[field])

    for name in data["company_names"]:
        related_entities.append({
            "type": "organisation",
            "value": name,
            "relationship": "published_on_website",
        })

    for name in data["published_individual_names"]:
        related_entities.append({
            "type": "person",
            "value": name,
            "relationship": "published_on_website",
        })

    for email in data["contact_email_addresses"]:
        related_entities.append({
            "type": "email_address",
            "value": email,
            "relationship": "published_on_website",
        })

    for telephone in data["telephone_numbers"]:
        related_entities.append({
            "type": "telephone_number",
            "value": telephone,
            "relationship": "published_on_website",
        })

    for hostname in data["external_service_domains"]:
        related_entities.append({
            "type": "domain",
            "value": hostname,
            "relationship": "external_website_resource",
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
    elif populated_fields:
        status = "success"
    else:
        status = "no_results"

    return make_envelope(
        status,
        data,
        provenance,
        related_entities,
        errors,
    )