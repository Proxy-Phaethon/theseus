import ipaddress
import socket

import requests

TIMEOUT = 15

DNS_ENDPOINT = "https://cloudflare-dns.com/dns-query"
RDAP_IP_ENDPOINT = "https://rdap.org/ip/{}"
BGPVIEW_ENDPOINT = "https://api.bgpview.io"

IPWHO_ENDPOINT = "https://ipwho.is/{}"

FIELDS = (
    "ipv4_addresses",
    "ipv6_addresses",
    "ip_ranges_cidr",
    "autonomous_system_numbers",
    "asn_organisation_names",
    "network_owner",
    "isp",
    "hosting_provider",
    "nameserver_ip_addresses",
    "mail_server_ip_addresses",
    "reverse_dns_hostnames",
    "cname_targets",
    "bgp_announced_prefixes",
    "origin_asns",
    "ip_allocation_organisations"
)

def empty_data():
    return {field: "none" for field in FIELDS}

def request_json(url, params=None):
    response = requests.get(
        url,
        params=params,
        headers={
            "Accept": "application/json",
            "User-Agent": "Theseus/1.0"
        },
        timeout=TIMEOUT
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

        for result in results:
            addresses.add(result[4][0])

    except socket.gaierror:
        pass

    return sorted(addresses)

def reverse_dns(ip):
    try:
        hostname, aliases, addresses = socket.gethostbyaddr(ip)

        results = [hostname]
        results.extend(aliases)

        return sorted(set(results))

    except (socket.herror, socket.gaierror, OSError):
        return []

def get_rdap_ip(ip):
    try:
        result = request_json(
            RDAP_IP_ENDPOINT.format(ip)
        )

        entities = []

        for entity in result.get("entities", []):

            vcard = entity.get("vcardArray", [])

            name = None

            if len(vcard) > 1:
                for item in vcard[1]:

                    if item[0] == "fn":
                        name = item[3]
                        break

            entities.append({
                "name": name,
                "roles": entity.get("roles", [])
            })

        return {
            "name": result.get("name"),
            "handle": result.get("handle"),
            "start_address": result.get("startAddress"),
            "end_address": result.get("endAddress"),
            "entities": entities
        }

    except (requests.RequestException, ValueError, TypeError):
        return None

def get_bgp_information(ip):
    try:
        result = request_json(
            f"{BGPVIEW_ENDPOINT}/ip/{ip}"
        )

        if result.get("status") != "ok":
            return []

        prefixes = result.get("data", {}).get("prefixes", [])

        return prefixes

    except (requests.RequestException, ValueError, TypeError):
        return []

def get_ipwho_information(ip):
    try:
        result = request_json(
            IPWHO_ENDPOINT.format(ip)
        )

        if not result.get("success"):
            return None

        connection = result.get("connection", {})

        return {
            "isp": connection.get("isp"),
            "organisation": connection.get("org"),
            "asn": connection.get("asn")
        }

    except (requests.RequestException, ValueError, TypeError):
        return None

def get_ip_ranges(rdap_records):
    ranges = set()

    for record in rdap_records:

        if not record:
            continue

        start = record.get("start_address")
        end = record.get("end_address")

        if not start or not end:
            continue

        try:
            start_ip = ipaddress.ip_address(start)
            end_ip = ipaddress.ip_address(end)

            if start_ip.version != end_ip.version:
                continue

            networks = ipaddress.summarize_address_range(
                start_ip,
                end_ip
            )

            ranges.update(str(network) for network in networks)

        except ValueError:
            continue

    return sorted(ranges)

def get_related_hostnames(domain):
    nameservers = [
        value.rstrip(".")
        for value in get_dns_records(domain, "NS")
    ]

    mail_servers = []

    for record in get_dns_records(domain, "MX"):

        parts = record.split()

        if parts:
            mail_servers.append(parts[-1].rstrip("."))

    return sorted(set(nameservers)), sorted(set(mail_servers))

def get_cname_targets(domain):
    return sorted({
        value.rstrip(".")
        for value in get_dns_records(domain, "CNAME")
    })

def run(domain: str) -> dict:
    data = empty_data()
    provenance = []
    related_entities = []

    try:
        domain_ips = resolve_hostname(domain)

        ipv4_addresses = sorted({
            ip for ip in domain_ips
            if ipaddress.ip_address(ip).version == 4
        })

        ipv6_addresses = sorted({
            ip for ip in domain_ips
            if ipaddress.ip_address(ip).version == 6
        })

        if ipv4_addresses:
            data["ipv4_addresses"] = ipv4_addresses

        if ipv6_addresses:
            data["ipv6_addresses"] = ipv6_addresses

        nameservers, mail_servers = get_related_hostnames(domain)

        nameserver_ips = {}
        mail_server_ips = {}

        for hostname in nameservers:
            addresses = resolve_hostname(hostname)

            if addresses:
                nameserver_ips[hostname] = addresses

        for hostname in mail_servers:
            addresses = resolve_hostname(hostname)

            if addresses:
                mail_server_ips[hostname] = addresses

        if nameserver_ips:
            data["nameserver_ip_addresses"] = nameserver_ips

        if mail_server_ips:
            data["mail_server_ip_addresses"] = mail_server_ips

        all_ips = set(domain_ips)

        for addresses in nameserver_ips.values():
            all_ips.update(addresses)

        for addresses in mail_server_ips.values():
            all_ips.update(addresses)

        reverse_records = {}

        for ip in sorted(all_ips):

            hostnames = reverse_dns(ip)

            if hostnames:
                reverse_records[ip] = hostnames

        if reverse_records:
            data["reverse_dns_hostnames"] = reverse_records

        cname_targets = get_cname_targets(domain)

        if cname_targets:
            data["cname_targets"] = cname_targets

            for target in cname_targets:
                related_entities.append({
                    "type": "hostname",
                    "value": target,
                    "relationship": "CNAME target"
                })

        rdap_records = []
        ipwho_records = []

        for ip in sorted(all_ips):

            rdap = get_rdap_ip(ip)

            if rdap:
                rdap_records.append(rdap)

                if rdap.get("name"):
                    related_entities.append({
                        "type": "network",
                        "value": rdap["name"],
                        "relationship": "IP allocation"
                    })

            ipwho = get_ipwho_information(ip)

            if ipwho:
                ipwho_records.append({
                    "ip": ip,
                    **ipwho
                })

        network_owners = sorted({
            record["name"]
            for record in rdap_records
            if record.get("name")
        })

        allocation_organisations = sorted({
            entity["name"]
            for record in rdap_records
            for entity in record.get("entities", [])
            if entity.get("name")
        })

        if network_owners:
            data["network_owner"] = network_owners

        if allocation_organisations:
            data["ip_allocation_organisations"] = (
                allocation_organisations
            )

        isps = sorted({
            record["isp"]
            for record in ipwho_records
            if record.get("isp")
        })

        providers = sorted({
            record["organisation"]
            for record in ipwho_records
            if record.get("organisation")
        })

        if isps:
            data["isp"] = isps

        if providers:
            data["hosting_provider"] = providers

        bgp_prefixes = {}
        origin_asns = set()
        asn_organisations = set()

        for ip in sorted(all_ips):

            prefixes = get_bgp_information(ip)

            for prefix in prefixes:

                prefix_value = prefix.get("prefix")

                if not prefix_value:
                    continue

                asn_data = prefix.get("asn", {})

                asn = asn_data.get("asn")
                asn_name = (
                    asn_data.get("name")
                    or asn_data.get("description")
                )

                bgp_prefixes[prefix_value] = {
                    "ip": ip,
                    "asn": asn,
                    "organisation": asn_name
                }

                if asn:
                    origin_asns.add(asn)

                if asn_name:
                    asn_organisations.add(asn_name)

        if bgp_prefixes:
            data["bgp_announced_prefixes"] = list(
                bgp_prefixes.values()
            )

        if origin_asns:
            data["origin_asns"] = sorted(origin_asns)

            data["autonomous_system_numbers"] = sorted(
                {f"AS{asn}" for asn in origin_asns}
            )

        if asn_organisations:
            data["asn_organisation_names"] = sorted(
                asn_organisations
            )

        cidr_ranges = get_ip_ranges(rdap_records)

        if cidr_ranges:
            data["ip_ranges_cidr"] = cidr_ranges

        if domain_ips:
            provenance.append({
                "source": "DNS",
                "description": "Domain address resolution",
                "url": DNS_ENDPOINT
            })

        if nameservers or mail_servers:
            provenance.append({
                "source": "DNS",
                "description": "NS and MX records",
                "url": DNS_ENDPOINT
            })

        if rdap_records:
            provenance.append({
                "source": "RDAP",
                "description": "IP allocation records",
                "url": "https://rdap.org/"
            })

        if ipwho_records:
            provenance.append({
                "source": "ipwho.is",
                "description": "ISP and network organisation",
                "url": IPWHO_ENDPOINT
            })

        if bgp_prefixes:
            provenance.append({
                "source": "BGPView",
                "description": "BGP prefixes and origin ASNs",
                "url": BGPVIEW_ENDPOINT
            })

        if reverse_records:
            provenance.append({
                "source": "Reverse DNS",
                "description": "PTR hostname resolution"
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
            "module": "network",
            "data": data,
            "provenance": provenance,
            "related_entities": related_entities
        }

    except Exception as exc:

        return {
            "status": "error",
            "module": "network",
            "data": data,
            "provenance": provenance,
            "related_entities": related_entities,
            "error": str(exc)
        }