import json
import re
import socket
import ssl

import requests

from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse

TIMEOUT = 15

RDAP_ENDPOINT = "https://rdap.org/domain/{}"
DNS_ENDPOINT = "https://cloudflare-dns.com/dns-query"
GEO_ENDPOINT = "https://ipwho.is/{}"
GEOCODE_ENDPOINT = "https://nominatim.openstreetmap.org/search"

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
    "website_contact_geography"
)

def empty_data():
    return {field: "none" for field in FIELDS}

def request_json(url, **kwargs):
    response = requests.get(
        url,
        timeout=TIMEOUT,
        **kwargs
    )
    response.raise_for_status()
    return response.json()

def get_dns_records(domain, record_type):
    try:
        result = request_json(
            DNS_ENDPOINT,
            params={
                "name": domain,
                "type": record_type
            },
            headers={"Accept": "application/dns-json"}
        )

        return [
            record["data"]
            for record in result.get("Answer", [])
            if "data" in record
        ]

    except requests.RequestException:
        return []

def get_ip_addresses(hostname):
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

def geolocate_ip(ip):
    try:
        result = request_json(
            GEO_ENDPOINT.format(ip)
        )

        if not result.get("success"):
            return None

        return {
            "ip": ip,
            "country": result.get("country") or "none",
            "region": result.get("region") or "none",
            "city": result.get("city") or "none",
            "postal_code": result.get("postal") or "none",
            "latitude": result.get("latitude"),
            "longitude": result.get("longitude"),
            "isp": result.get("connection", {}).get(
                "isp", "none"
            )
        }

    except (requests.RequestException, ValueError):
        return None

def get_rdap_location(domain):
    try:
        result = request_json(
            RDAP_ENDPOINT.format(domain)
        )

        for entity in result.get("entities", []):

            if "registrant" not in entity.get("roles", []):
                continue

            vcard = entity.get("vcardArray", [])

            if len(vcard) < 2:
                continue

            for item in vcard[1]:

                if item[0] == "adr" and isinstance(item[3], list):

                    address = item[3]

                    return {
                        "address": ", ".join(
                            str(part) for part in address if part
                        ) or "none",
                        "city": address[3] or "none",
                        "region": address[4] or "none",
                        "postal_code": address[5] or "none",
                        "country": address[6] or "none"
                    }

    except (requests.RequestException, ValueError, TypeError):
        pass

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

        if tag == "script" and attrs.get("type") == "application/ld+json":
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

def collect_addresses(data):
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
                "addressCountry"
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
            if key in ("address",):
                continue

            if isinstance(value, (dict, list)):
                addresses.extend(collect_addresses(value))

    return addresses

def extract_website_addresses(domain):
    base_url = f"https://{domain}"

    urls = [base_url]
    addresses = []
    contact_geography = []

    session = requests.Session()

    headers = {
        "User-Agent": "Theseus/1.0 (public domain research)"
    }

    for url in urls:

        try:
            response = session.get(
                url,
                headers=headers,
                timeout=TIMEOUT
            )

            response.raise_for_status()

            parser = WebsiteParser()
            parser.feed(response.text)

            for script in parser.jsonld:

                try:
                    structured_data = json.loads(script)

                    addresses.extend(
                        collect_addresses(structured_data)
                    )

                except (ValueError, TypeError):
                    continue

            if url == base_url:

                for link in parser.links[:5]:

                    candidate = urljoin(base_url, link)

                    if urlparse(candidate).hostname == urlparse(base_url).hostname:
                        urls.append(candidate)

        except requests.RequestException:
            continue

    unique_addresses = []

    for address in addresses:

        if address not in unique_addresses:
            unique_addresses.append(address)

    for address in unique_addresses:

        contact_geography.append({
            "source": "website structured data",
            **address
        })

    return unique_addresses, contact_geography

def get_certificate_country(domain):
    try:
        context = ssl.create_default_context()

        with socket.create_connection(
            (domain, 443),
            timeout=TIMEOUT
        ) as connection:

            with context.wrap_socket(
                connection,
                server_hostname=domain
            ) as secure_socket:

                certificate = secure_socket.getpeercert()

                for group in certificate.get("subject", []):

                    for key, value in group:

                        if key == "countryName":
                            return value

    except (OSError, ssl.SSLError, ValueError):
        pass

    return None

def run(domain: str) -> dict:
    data = empty_data()
    provenance = []
    related_entities = []

    try:
        registrant = get_rdap_location(domain)

        if registrant:

            data["registrant_country"] = registrant["country"]
            data["registrant_region"] = registrant["region"]
            data["registrant_city"] = registrant["city"]
            data["registrant_address"] = registrant["address"]
            data["registrant_postal_code"] = registrant["postal_code"]

            provenance.append({
                "source": "RDAP",
                "url": RDAP_ENDPOINT.format(domain)
            })

        domain_ips = get_ip_addresses(domain)

        ip_locations = []

        for ip in domain_ips:

            location = geolocate_ip(ip)

            if location:
                ip_locations.append(location)

        if ip_locations:

            data["ip_geolocation"] = ip_locations

            data["hosting_country"] = sorted({
                item["country"]
                for item in ip_locations
                if item["country"] != "none"
            }) or "none"

            data["hosting_city"] = sorted({
                item["city"]
                for item in ip_locations
                if item["city"] != "none"
            }) or "none"

            provenance.append({
                "source": "ipwho.is",
                "description": "IP geolocation"
            })

            for location in ip_locations:
                related_entities.append({
                    "type": "ip_address",
                    "value": location["ip"],
                    "country": location["country"]
                })

        nameservers = get_dns_records(domain, "NS")
        nameserver_locations = []

        for nameserver in nameservers:

            hostname = nameserver.rstrip(".")
            addresses = get_ip_addresses(hostname)

            for ip in addresses:

                location = geolocate_ip(ip)

                if location:
                    nameserver_locations.append({
                        "hostname": hostname,
                        **location
                    })

        if nameserver_locations:
            data["nameserver_locations"] = nameserver_locations

        mail_servers = get_dns_records(domain, "MX")
        mail_locations = []

        for record in mail_servers:

            parts = record.split()

            hostname = parts[-1].rstrip(".") if parts else None

            if not hostname:
                continue

            for ip in get_ip_addresses(hostname):

                location = geolocate_ip(ip)

                if location:
                    mail_locations.append({
                        "hostname": hostname,
                        **location
                    })

        if mail_locations:
            data["mail_server_locations"] = mail_locations

        if ip_locations:

            data["cdn_edge_locations"] = [
                item for item in ip_locations
                if any(
                    keyword in item.get("isp", "").lower()
                    for keyword in (
                        "cloudflare",
                        "akamai",
                        "fastly",
                        "amazon",
                        "cloudfront"
                    )
                )
            ] or "none"

        certificate_country = get_certificate_country(domain)

        if certificate_country:
            data["certificate_organisation_country"] = (
                certificate_country
            )

            provenance.append({
                "source": "TLS certificate",
                "description": "Certificate subject country"
            })

        addresses, contact_geography = extract_website_addresses(
            domain
        )

        if addresses:
            data["public_business_addresses"] = addresses

            data["website_contact_geography"] = (
                contact_geography
            )

            provenance.append({
                "source": "Website",
                "description": "Public structured contact information"
            })

        populated = sum(
            value != "none" for value in data.values()
        )

        status = (
            "success"
            if populated == len(FIELDS)
            else "partial" if populated else "error"
        )

        return {
            "status": status,
            "module": "geography",
            "data": data,
            "provenance": provenance,
            "related_entities": related_entities
        }

    except Exception as exc:

        return {
            "status": "error",
            "module": "geography",
            "data": data,
            "provenance": provenance,
            "related_entities": related_entities,
            "error": str(exc)
        }