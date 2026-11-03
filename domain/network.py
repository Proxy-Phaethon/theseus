import ipaddress
import socket
import requests

from datetime import datetime, timezone

MODULE_NAME = "network"

TIMEOUT = 15
MAX_IP_LOOKUPS = 30

DNS_ENDPOINT = "https://cloudflare-dns.com/dns-query"
RDAP_IP_ENDPOINT = "https://rdap.org/ip/{}"
BGPVIEW_ENDPOINT = "https://api.bgpview.io"
IPWHO_ENDPOINT = "https://ipwho.is/{}"

HEADERS = {
    "Accept": "application/json",
    "User-Agent": "Theseus/1.0"
}

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

def empty_data() -> dict:
    return {
        field: None if field in (
            "ipv4_addresses",
            "ipv6_addresses",
            "ip_ranges_cidr",
            "autonomous_system_numbers",
            "asn_organisation_names",
            "network_owner",
            "isp",
            "hosting_provider",
            "cname_targets",
            "bgp_announced_prefixes",
            "origin_asns",
            "ip_allocation_organisations"
        ) else []
        for field in FIELDS
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

        records = [
            record["data"]
            for record in result.get("Answer", [])
            if isinstance(record, dict) and "data" in record
        ]

        return records, [], True

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

def reverse_dns(ip: str) -> tuple:
    try:
        hostname, aliases, addresses = socket.gethostbyaddr(ip)

        results = sorted({
            value.lower().rstrip(".")
            for value in [hostname, *aliases]
            if value
        })

        return results, [], True

    except (socket.herror, socket.gaierror, OSError) as exc:
        return (
            [],
            [f"Reverse DNS lookup for {ip} failed: {exc}"],
            False
        )

def get_rdap_ip(ip: str) -> tuple:
    try:
        result = request_json(
            RDAP_IP_ENDPOINT.format(ip)
        )

        if not isinstance(result, dict):
            raise ValueError(
                "RDAP returned an unexpected response."
            )

        entities = []

        for entity in result.get("entities", []):
            if not isinstance(entity, dict):
                continue

            vcard = entity.get("vcardArray", [])
            name = None

            if (
                isinstance(vcard, list)
                and len(vcard) > 1
                and isinstance(vcard[1], list)
            ):
                for item in vcard[1]:
                    if (
                        isinstance(item, list)
                        and len(item) >= 4
                        and item[0] == "fn"
                    ):
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
        }, [], True

    except (
        requests.RequestException,
        ValueError,
        TypeError
    ) as exc:
        return (
            None,
            [f"RDAP lookup for {ip} failed: {exc}"],
            False
        )

def get_bgp_information(ip: str) -> tuple:
    try:
        result = request_json(
            f"{BGPVIEW_ENDPOINT}/ip/{ip}"
        )

        if not isinstance(result, dict):
            raise ValueError(
                "BGPView returned an unexpected response."
            )

        if result.get("status") != "ok":
            raise ValueError(
                f"BGPView returned status: {result.get('status')}"
            )

        prefixes = (
            result.get("data", {}).get("prefixes", [])
        )

        return prefixes, [], True

    except (
        requests.RequestException,
        ValueError,
        TypeError
    ) as exc:
        return (
            [],
            [f"BGP lookup for {ip} failed: {exc}"],
            False
        )

def get_ipwho_information(ip: str) -> tuple:
    try:
        result = request_json(
            IPWHO_ENDPOINT.format(ip)
        )

        if not isinstance(result, dict):
            raise ValueError(
                "IP geolocation service returned an unexpected response."
            )

        if not result.get("success"):
            raise ValueError(
                result.get("message", "IP lookup was unsuccessful.")
            )

        connection = result.get("connection") or {}

        return {
            "isp": connection.get("isp"),
            "organisation": connection.get("org"),
            "asn": connection.get("asn")
        }, [], True

    except (
        requests.RequestException,
        ValueError,
        TypeError
    ) as exc:
        return (
            None,
            [f"IP information lookup for {ip} failed: {exc}"],
            False
        )

def get_ip_ranges(rdap_records: list) -> list:
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

            ranges.update(
                str(network)
                for network in networks
            )

        except ValueError:
            continue

    return sorted(ranges)

def get_related_hostnames(domain: str):
    nameservers, ns_errors, ns_success = get_dns_records(
        domain,
        "NS"
    )

    mail_records, mx_errors, mx_success = get_dns_records(
        domain,
        "MX"
    )

    nameservers = sorted({
        value.rstrip(".").lower()
        for value in nameservers
    })

    mail_servers = set()

    for record in mail_records:
        parts = record.split()

        if parts:
            mail_servers.add(
                parts[-1].rstrip(".").lower()
            )

    return (
        nameservers,
        sorted(mail_servers),
        ns_errors + mx_errors,
        ns_success,
        mx_success
    )

def get_cname_targets(domain: str):
    records, errors, succeeded = get_dns_records(
        domain,
        "CNAME"
    )

    targets = sorted({
        value.rstrip(".").lower()
        for value in records
    })

    return targets, errors, succeeded

def run(domain: str) -> dict:
    data = empty_data()
    provenance = []
    related_entities = []
    errors = []

    successful_sources = 0

    try:
        domain_ips, source_errors, dns_success = (
            resolve_hostname(domain)
        )
        errors.extend(source_errors)

        if dns_success:
            successful_sources += 1

            add_provenance(
                provenance,
                "System DNS resolver",
                "Domain address resolution"
            )

        ipv4_addresses = sorted({
            ip for ip in domain_ips
            if ipaddress.ip_address(ip).version == 4
        })

        ipv6_addresses = sorted({
            ip for ip in domain_ips
            if ipaddress.ip_address(ip).version == 6
        })

        data["ipv4_addresses"] = ipv4_addresses
        data["ipv6_addresses"] = ipv6_addresses

        (
            nameservers,
            mail_servers,
            source_errors,
            ns_success,
            mx_success
        ) = get_related_hostnames(domain)

        errors.extend(source_errors)

        if ns_success:
            successful_sources += 1

            add_provenance(
                provenance,
                DNS_ENDPOINT,
                "Nameserver record retrieval"
            )

        if mx_success:
            successful_sources += 1

            add_provenance(
                provenance,
                DNS_ENDPOINT,
                "Mail exchanger record retrieval"
            )

        nameserver_ips = {}
        mail_server_ips = {}

        for hostname in nameservers:
            addresses, source_errors, succeeded = (
                resolve_hostname(hostname)
            )
            errors.extend(source_errors)

            if succeeded:
                successful_sources += 1

            if addresses:
                nameserver_ips[hostname] = addresses

        for hostname in mail_servers:
            addresses, source_errors, succeeded = (
                resolve_hostname(hostname)
            )
            errors.extend(source_errors)

            if succeeded:
                successful_sources += 1

            if addresses:
                mail_server_ips[hostname] = addresses

        data["nameserver_ip_addresses"] = nameserver_ips
        data["mail_server_ip_addresses"] = mail_server_ips

        all_ips = set(domain_ips)

        for addresses in nameserver_ips.values():
            all_ips.update(addresses)

        for addresses in mail_server_ips.values():
            all_ips.update(addresses)

        all_ips = sorted(all_ips)[:MAX_IP_LOOKUPS]

        reverse_records = {}

        for ip in all_ips:
            hostnames, source_errors, succeeded = reverse_dns(ip)
            errors.extend(source_errors)

            if succeeded:
                successful_sources += 1

            if hostnames:
                reverse_records[ip] = hostnames

        data["reverse_dns_hostnames"] = reverse_records

        cname_targets, source_errors, cname_success = (
            get_cname_targets(domain)
        )
        errors.extend(source_errors)

        if cname_success:
            successful_sources += 1

            add_provenance(
                provenance,
                DNS_ENDPOINT,
                "Canonical hostname record retrieval"
            )

        data["cname_targets"] = cname_targets

        rdap_records = []
        ipwho_records = []

        for ip in all_ips:
            rdap, source_errors, rdap_success = get_rdap_ip(ip)
            errors.extend(source_errors)

            if rdap_success:
                successful_sources += 1

                if rdap:
                    rdap_records.append(rdap)

            ipwho, source_errors, ipwho_success = (
                get_ipwho_information(ip)
            )
            errors.extend(source_errors)

            if ipwho_success:
                successful_sources += 1

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

        data["network_owner"] = network_owners
        data["ip_allocation_organisations"] = (
            allocation_organisations
        )

        isps = sorted({
            record["isp"]
            for record in ipwho_records
            if record.get("isp")
        })

        organisations = sorted({
            record["organisation"]
            for record in ipwho_records
            if record.get("organisation")
        })

        data["isp"] = isps

        data["hosting_provider"] = organisations

        bgp_prefixes = {}
        origin_asns = set()
        asn_organisations = set()

        for ip in all_ips:
            prefixes, source_errors, bgp_success = (
                get_bgp_information(ip)
            )
            errors.extend(source_errors)

            if bgp_success:
                successful_sources += 1

            for prefix in prefixes:
                if not isinstance(prefix, dict):
                    continue

                prefix_value = prefix.get("prefix")

                if not prefix_value:
                    continue

                asn_data = prefix.get("asn") or {}

                if not isinstance(asn_data, dict):
                    asn_data = {}

                asn = asn_data.get("asn")
                asn_name = (
                    asn_data.get("name")
                    or asn_data.get("description")
                )

                key = (prefix_value, asn)

                bgp_prefixes[key] = {
                    "prefix": prefix_value,
                    "ip": ip,
                    "asn": asn,
                    "organisation": asn_name
                }

                if asn is not None:
                    origin_asns.add(asn)

                if asn_name:
                    asn_organisations.add(asn_name)

        data["bgp_announced_prefixes"] = list(
            bgp_prefixes.values()
        )

        data["origin_asns"] = sorted(
            origin_asns,
            key=lambda value: int(value)
        )

        data["autonomous_system_numbers"] = sorted({
            f"AS{asn}"
            for asn in origin_asns
        })

        data["asn_organisation_names"] = sorted(
            asn_organisations
        )

        data["ip_ranges_cidr"] = get_ip_ranges(
            rdap_records
        )

        for ip in sorted(all_ips):
            related_entities.append({
                "type": "ip_address",
                "value": ip,
                "relationship": "resolved_infrastructure_address"
            })

        for hostname in nameservers:
            related_entities.append({
                "type": "hostname",
                "value": hostname,
                "relationship": "nameserver"
            })

        for hostname in mail_servers:
            related_entities.append({
                "type": "hostname",
                "value": hostname,
                "relationship": "mail_server"
            })

        for hostname in cname_targets:
            related_entities.append({
                "type": "hostname",
                "value": hostname,
                "relationship": "cname_target"
            })

        for ip, hostnames in reverse_records.items():
            for hostname in hostnames:
                related_entities.append({
                    "type": "hostname",
                    "value": hostname,
                    "relationship": "reverse_dns_record"
                })

        for asn in origin_asns:
            related_entities.append({
                "type": "autonomous_system",
                "value": f"AS{asn}",
                "relationship": "bgp_origin"
            })

        for organisation in (
            network_owners + allocation_organisations
        ):
            related_entities.append({
                "type": "organisation",
                "value": organisation,
                "relationship": "ip_allocation_association"
            })

        seen = set()
        unique_entities = []

        for entity in related_entities:
            key = (
                entity["type"],
                entity["value"].lower(),
                entity["relationship"]
            )

            if key not in seen:
                seen.add(key)
                unique_entities.append(entity)

        related_entities = unique_entities

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
        errors.append(
            f"Network extraction failed: {exc}"
        )

        return make_envelope(
            status="error",
            data=data,
            provenance=provenance,
            related_entities=related_entities,
            errors=errors
        )