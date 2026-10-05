from __future__ import annotations

from collections import Counter, defaultdict
from typing import Any

class IPResponder:
    def respond(
        self,
        entity,
        results: list[tuple[str, Any]],
        failures: list[dict[str, str]] | None = None,
    ) -> str:
        observations = self._collect_observations(results)

        sections = [
            self._identity(observations),
            self._network(observations),
            self._location(observations),
            self._cloud_hosting(observations),
            self._exposure(observations),
            self._services(observations),
            self._web(observations),
            self._tls(observations),
            self._passive_dns(observations),
            self._reverse_dns(observations),
            self._reputation(observations),
            self._threats(observations),
            self._anonymizer(observations),
            self._temporal(observations),
            self._observations(observations),
            self._sources(results, failures or []),
        ]

        return "\n\n".join(
            section
            for section in sections
            if section
        )

    def _collect_observations(
        self,
        results: list[tuple[str, Any]],
    ) -> dict[str, Any]:
        data: dict[str, Any] = {
            "identity": [],
            "organization": [],
            "hostname": [],
            "asn": [],
            "prefix": [],
            "location": [],
            "cloud": [],
            "hosting": [],
            "services": [],
            "web": [],
            "tls": [],
            "passive_dns": [],
            "reverse_dns": [],
            "reputation": [],
            "threats": [],
            "anonymizer": [],
            "temporal": [],
        }

        for source, result in results:
            if not isinstance(result, dict):
                continue

            self._extract_source(
                source,
                result,
                data,
            )

        return data

    def _extract_source(
        self,
        source: str,
        result: dict[str, Any],
        data: dict[str, Any],
    ) -> None:
        if source == "CensysTool":
            self._extract_censys(source, result, data)

        elif source == "IPInfoTool":
            self._extract_ipinfo(source, result, data)

        elif source == "IPAPITool":
            self._extract_ip_api(source, result, data)

        elif source == "IPAPIIsTool":
            self._extract_ipapi_is(source, result, data)

        elif source == "RIPEstatTool":
            self._extract_ripestat(source, result, data)

        elif source == "PeeringDBTool":
            self._extract_peeringdb(source, result, data)

        elif source == "TeamCymruTool":
            self._extract_team_cymru(source, result, data)

        elif source == "AbuseIPDBTool":
            self._extract_abuseipdb(source, result, data)

        elif source == "AlienVaultOTXTool":
            self._extract_otx(source, result, data)

        elif source == "VirusTotalTool":
            self._extract_virustotal(source, result, data)

        elif source == "TorExitListTool":
            self._extract_tor(source, result, data)

        elif source == "X4BNetTool":
            self._extract_x4bnet(source, result, data)

        elif source == "RobtexTool":
            self._extract_robtex(source, result, data)

        elif source == "TLSXTool":
            self._extract_tlsx(source, result, data)

        elif source == "ShodanTool":
            self._extract_shodan(source, result, data)

        elif source == "NetlasTool":
            self._extract_netlas(source, result, data)

    def _extract_censys(self, source, result, data):
        resource = result.get("result", {}).get("resource", {})

        location = resource.get("location", {})
        self._add_location(
            data,
            source,
            country=location.get("country"),
            country_code=location.get("country_code"),
            region=location.get("province"),
            city=location.get("city"),
            latitude=self._nested(
                location,
                "coordinates",
                "latitude",
            ),
            longitude=self._nested(
                location,
                "coordinates",
                "longitude",
            ),
            timezone=location.get("timezone"),
        )

        asn = resource.get("autonomous_system", {})
        self._add(
            data,
            "asn",
            asn.get("asn"),
            source,
        )

        self._add(
            data,
            "organization",
            asn.get("description") or asn.get("name"),
            source,
        )

        self._add(
            data,
            "prefix",
            asn.get("bgp_prefix"),
            source,
        )

        whois = resource.get("whois", {})
        network = whois.get("network", {})

        self._add(
            data,
            "organization",
            network.get("name"),
            source,
        )

        for service in resource.get("services", []):
            data["services"].append({
                "source": source,
                "port": service.get("port"),
                "protocol": service.get("protocol"),
                "transport": service.get("transport_protocol"),
                "scan_time": service.get("scan_time"),
            })

        for endpoint in resource.get("endpoints", []):
            http = endpoint.get("http", {})

            if http:
                data["web"].append({
                    "source": source,
                    "host": endpoint.get("hostname"),
                    "port": endpoint.get("port"),
                    "status": http.get("status_code"),
                    "title": http.get("html_title"),
                    "url": http.get("uri"),
                    "redirects": http.get("redirect_chain", []),
                    "scan_time": endpoint.get("scan_time"),
                })

        dns = resource.get("dns", {})

        reverse = dns.get("reverse_dns", {})
        for name in reverse.get("names", []):
            self._add(
                data,
                "reverse_dns",
                name,
                source,
            )

        for name in dns.get("names", []):
            self._add(
                data,
                "passive_dns",
                name,
                source,
            )

        for service in resource.get("services", []):
            cert = service.get("cert")

            if cert:
                parsed = cert.get("parsed", {})

                data["tls"].append({
                    "source": source,
                    "port": service.get("port"),
                    "subject": parsed.get("subject_dn"),
                    "issuer": parsed.get("issuer_dn"),
                    "not_before": self._nested(
                        parsed,
                        "validity_period",
                        "not_before",
                    ),
                    "not_after": self._nested(
                        parsed,
                        "validity_period",
                        "not_after",
                    ),
                    "sha256": cert.get(
                        "fingerprint_sha256"
                    ),
                    "names": cert.get("names", []),
                })

        for event in resource.get("whois", {}).get("events", []):
            data["temporal"].append({
                "source": source,
                "type": event.get("event_action"),
                "date": event.get("event_date"),
            })

    def _extract_ipinfo(self, source, result, data):
        self._add(
            data,
            "hostname",
            result.get("hostname"),
            source,
        )

        self._add(
            data,
            "organization",
            result.get("org"),
            source,
        )

        self._add_location(
            data,
            source,
            country=result.get("country"),
            region=result.get("region"),
            city=result.get("city"),
            postal=result.get("postal"),
            timezone=result.get("timezone"),
            coordinates=result.get("loc"),
        )

        self._add(
            data,
            "cloud",
            result.get("anycast"),
            source,
            label="anycast",
        )

    def _extract_ip_api(self, source, result, data):
        self._add(
            data,
            "organization",
            result.get("org") or result.get("isp"),
            source,
        )

        self._add(
            data,
            "hostname",
            result.get("reverse"),
            source,
        )

        self._add(
            data,
            "asn",
            result.get("as"),
            source,
        )

        self._add_location(
            data,
            source,
            country=result.get("country"),
            country_code=result.get("countryCode"),
            region=result.get("regionName"),
            city=result.get("city"),
            postal=result.get("zip"),
            timezone=result.get("timezone"),
            latitude=result.get("lat"),
            longitude=result.get("lon"),
        )

        self._add(
            data,
            "hosting",
            result.get("hosting"),
            source,
        )

    def _extract_ipapi_is(self, source, result, data):
        self._add(
            data,
            "organization",
            result.get("company"),
            source,
        )

        self._add(
            data,
            "asn",
            result.get("asn"),
            source,
        )

        self._add_location(
            data,
            source,
            country=result.get("country"),
            region=result.get("region"),
            city=result.get("city"),
            timezone=result.get("timezone"),
            latitude=result.get("lat"),
            longitude=result.get("lon"),
        )

    def _extract_ripestat(self, source, result, data):
        info = result.get("data", {})

        for asn in info.get("asns", []):
            self._add(
                data,
                "asn",
                asn,
                source,
            )

        self._add(
            data,
            "prefix",
            info.get("prefix"),
            source,
        )

    def _extract_peeringdb(self, source, result, data):
        for network in result.get("data", []):
            self._add(
                data,
                "asn",
                network.get("asn"),
                source,
            )

            self._add(
                data,
                "organization",
                network.get("name"),
                source,
            )

    def _extract_team_cymru(self, source, result, data):
        for item in result.get("results", []):
            self._add(
                data,
                "asn",
                item.get("asn"),
                source,
            )

            self._add(
                data,
                "prefix",
                item.get("prefix"),
                source,
            )

            self._add_location(
                data,
                source,
                country_code=item.get("country"),
            )

    def _extract_abuseipdb(self, source, result, data):
        item = result.get("data", {})

        data["reputation"].append({
            "source": source,
            "abuse_confidence": item.get(
                "abuseConfidenceScore"
            ),
            "is_whitelisted": item.get(
                "isWhitelisted"
            ),
            "total_reports": item.get(
                "totalReports"
            ),
            "distinct_reporters": item.get(
                "numDistinctUsers"
            ),
            "is_tor": item.get("isTor"),
            "usage_type": item.get("usageType"),
        })

        self._add(
            data,
            "organization",
            item.get("isp"),
            source,
        )

        self._add(
            data,
            "hostname",
            (item.get("hostnames") or [None])[0],
            source,
        )

    def _extract_otx(self, source, result, data):
        self._add(
            data,
            "organization",
            result.get("asn"),
            source,
        )

        self._add(
            data,
            "asn",
            result.get("asn"),
            source,
        )

        geo = result.get("geo", {})

        self._add_location(
            data,
            source,
            country=geo.get("country_name"),
            country_code=geo.get("country_code2"),
            continent=geo.get("continent_code"),
            latitude=geo.get("latitude"),
            longitude=geo.get("longitude"),
        )

        data["reputation"].append({
            "source": source,
            "reputation": result.get("reputation"),
            "validation": result.get("validation"),
            "false_positive": result.get(
                "false_positive"
            ),
        })

    def _extract_virustotal(self, source, result, data):
        attributes = (
            result.get("data", {})
            .get("attributes", {})
        )

        self._add(
            data,
            "asn",
            attributes.get("asn"),
            source,
        )

        self._add(
            data,
            "organization",
            attributes.get("as_owner"),
            source,
        )

        self._add_location(
            data,
            source,
            country=attributes.get("country"),
            continent=attributes.get("continent"),
        )

        self._add(
            data,
            "prefix",
            attributes.get("network"),
            source,
        )

        analysis = attributes.get(
            "last_analysis_stats",
            {},
        )

        if analysis:
            data["reputation"].append({
                "source": source,
                "analysis": analysis,
                "reputation": attributes.get(
                    "reputation"
                ),
                "votes": attributes.get(
                    "total_votes"
                ),
            })

        for context in attributes.get(
            "crowdsourced_context",
            [],
        ):
            data["threats"].append({
                "source": source,
                "title": context.get("title"),
                "severity": context.get("severity"),
                "details": context.get("details"),
                "timestamp": context.get("timestamp"),
            })

        certificate = attributes.get(
            "last_https_certificate",
            {},
        )

        if certificate:
            data["tls"].append({
                "source": source,
                "subject": self._nested(
                    certificate,
                    "subject",
                    "CN",
                ),
                "issuer": self._nested(
                    certificate,
                    "issuer",
                    "CN",
                ),
                "not_before": self._nested(
                    certificate,
                    "validity",
                    "not_before",
                ),
                "not_after": self._nested(
                    certificate,
                    "validity",
                    "not_after",
                ),
                "sha256": certificate.get(
                    "thumbprint_sha256"
                ),
                "names": self._nested(
                    certificate,
                    "extensions",
                    "subject_alternative_name",
                ) or [],
            })

    def _extract_tor(self, source, result, data):
        data["anonymizer"].append({
            "source": source,
            "type": "Tor",
            "active": result.get("is_tor_exit"),
        })

    def _extract_x4bnet(self, source, result, data):
        data["anonymizer"].append({
            "source": source,
            "type": "VPN",
            "active": result.get("is_vpn"),
            "networks": result.get(
                "matching_networks",
                [],
            ),
        })

    def _extract_robtex(self, source, result, data):
        self._add(
            data,
            "asn",
            result.get("asn"),
            source,
        )

        self._add(
            data,
            "organization",
            result.get("asn_name"),
            source,
        )

        self._add(
            data,
            "prefix",
            result.get("bgp_route"),
            source,
        )

        for item in result.get("pas", []):
            if isinstance(item, dict):
                name = (
                    item.get("hostname")
                    or item.get("domain")
                )
                self._add(
                    data,
                    "passive_dns",
                    name,
                    source,
                )

    def _extract_tlsx(self, source, result, data):
        for item in result.get("results", []):
            data["tls"].append({
                "source": source,
                "host": item.get("host"),
                "port": item.get("port"),
                "tls_version": item.get("tls_version"),
                "cipher": item.get("cipher"),
                "subject": item.get("subject_dn"),
                "issuer": item.get("issuer_dn"),
                "names": item.get("subject_an"),
                "sha256": item.get(
                    "certificate_sha256"
                ),
                "timestamp": item.get("timestamp"),
            })

    def _extract_shodan(self, source, result, data):
        self._add(
            data,
            "hostname",
            result.get("hostnames", [None])[0]
            if result.get("hostnames")
            else None,
            source,
        )

        self._add(
            data,
            "organization",
            result.get("org"),
            source,
        )

        self._add(
            data,
            "asn",
            result.get("asn"),
            source,
        )

        self._add(
            data,
            "prefix",
            result.get("data", {}).get("asn")
            if isinstance(result.get("data"), dict)
            else None,
            source,
        )

        for item in result.get("data", []):
            if isinstance(item, dict):
                data["services"].append({
                    "source": source,
                    "port": item.get("port"),
                    "protocol": item.get("transport"),
                    "service": item.get("product"),
                    "version": item.get("version"),
                    "timestamp": item.get("timestamp"),
                })

    def _extract_netlas(self, source, result, data):
        host = result.get("host", result)

        if not isinstance(host, dict):
            return

        self._add(
            data,
            "hostname",
            host.get("hostname"),
            source,
        )

        self._add(
            data,
            "organization",
            host.get("organization"),
            source,
        )

        self._add(
            data,
            "asn",
            host.get("asn"),
            source,
        )

        self._add(
            data,
            "prefix",
            host.get("route"),
            source,
        )

    @staticmethod
    def _add(
        data: dict[str, Any],
        field: str,
        value: Any,
        source: str,
        label: str | None = None,
    ) -> None:
        if value in (None, "", [], {}):
            return

        data[field].append({
            "source": source,
            "value": value,
            "label": label,
        })

    @staticmethod
    def _add_location(
        data: dict[str, Any],
        source: str,
        **values,
    ) -> None:
        cleaned = {
            key: value
            for key, value in values.items()
            if value not in (None, "")
        }

        if cleaned:
            cleaned["source"] = source
            data["location"].append(cleaned)

    @staticmethod
    def _nested(
        value: dict[str, Any],
        *keys: str,
    ) -> Any:
        current = value

        for key in keys:
            if not isinstance(current, dict):
                return None
            current = current.get(key)

        return current

    @staticmethod
    def _consensus(
        observations: list[dict[str, Any]],
    ) -> tuple[Any | None, list[tuple[Any, int]]]:
        if not observations:
            return None, []

        counts: Counter = Counter(
            str(item["value"])
            for item in observations
        )

        ordered = counts.most_common()

        winner_string, winner_count = ordered[0]

        winner = next(
            item["value"]
            for item in observations
            if str(item["value"]) == winner_string
        )

        return winner, [
            (value, count)
            for value, count in ordered
            if count < winner_count
        ]

    @staticmethod
    def _format_value(value: Any) -> str:
        if isinstance(value, bool):
            return "Yes" if value else "No"

        return str(value)

    def _identity(self, data):
        hostname, conflicts = self._consensus(
            data["hostname"]
        )
        organization, _ = self._consensus(
            data["organization"]
        )

        lines = ["Identity"]

        if hostname:
            lines.append(
                f"  Hostname: {hostname}"
            )

        if organization:
            lines.append(
                f"  Organization: {organization}"
            )

        return "\n".join(lines)

    def _network(self, data):
        asn, _ = self._consensus(data["asn"])
        prefix, _ = self._consensus(data["prefix"])

        lines = ["Network / ASN"]

        if asn:
            lines.append(f"  ASN: AS{str(asn).removeprefix('AS')}")

        if prefix:
            lines.append(f"  Prefix: {prefix}")

        return "\n".join(lines)

    def _location(self, data):
        if not data["location"]:
            return ""

        countries = [
            item.get("country")
            or item.get("country_code")
            for item in data["location"]
            if item.get("country")
            or item.get("country_code")
        ]

        cities = [
            item.get("city")
            for item in data["location"]
            if item.get("city")
        ]

        regions = [
            item.get("region")
            for item in data["location"]
            if item.get("region")
        ]

        country = self._majority(countries)
        city = self._majority(cities)
        region = self._majority(regions)

        lines = ["Location"]

        if country:
            lines.append(f"  Country: {country}")

        if region:
            lines.append(f"  Region: {region}")

        if city:
            lines.append(f"  City: {city}")

        return "\n".join(lines)

    def _cloud_hosting(self, data):
        lines = ["Cloud / Hosting"]

        hosting = [
            item["value"]
            for item in data["hosting"]
        ]

        cloud = [
            item["value"]
            for item in data["cloud"]
        ]

        if hosting:
            lines.append(
                f"  Hosting: {self._format_value(self._majority(hosting))}"
            )

        if cloud:
            lines.append(
                f"  Anycast: {self._format_value(self._majority(cloud))}"
            )

        return (
            "\n".join(lines)
            if len(lines) > 1
            else ""
        )

    def _exposure(self, data):
        if not data["services"]:
            return ""

        ports = sorted({
            item["port"]
            for item in data["services"]
            if item.get("port") is not None
        })

        lines = ["Exposure"]

        if ports:
            lines.append(
                "  Observed ports: "
                + ", ".join(map(str, ports))
            )

        return "\n".join(lines)

    def _services(self, data):
        if not data["services"]:
            return ""

        lines = ["Services"]

        seen = set()

        for service in data["services"]:
            key = (
                service.get("port"),
                service.get("protocol"),
                service.get("transport"),
            )

            if key in seen:
                continue

            seen.add(key)

            parts = []

            if service.get("port") is not None:
                parts.append(
                    f"Port {service['port']}"
                )

            if service.get("protocol"):
                parts.append(
                    service["protocol"]
                )

            if service.get("transport"):
                parts.append(
                    f"({service['transport']})"
                )

            if parts:
                lines.append(
                    "  " + " ".join(parts)
                )

        return "\n".join(lines)

    def _web(self, data):
        if not data["web"]:
            return ""

        lines = ["Web"]

        seen = set()

        for item in data["web"]:
            key = (
                item.get("host"),
                item.get("port"),
                item.get("status"),
                item.get("url"),
            )

            if key in seen:
                continue

            seen.add(key)

            line = []

            if item.get("host"):
                line.append(item["host"])

            if item.get("port"):
                line.append(f":{item['port']}")

            if item.get("status"):
                line.append(
                    f"HTTP {item['status']}"
                )

            if item.get("title"):
                line.append(
                    f"({item['title']})"
                )

            if line:
                lines.append(
                    "  " + " ".join(line)
                )

            if item.get("url"):
                lines.append(
                    f"    URL: {item['url']}"
                )

        return "\n".join(lines)

    def _tls(self, data):
        if not data["tls"]:
            return ""

        lines = ["TLS"]

        seen = set()

        for item in data["tls"]:
            key = (
                item.get("port"),
                item.get("subject"),
                item.get("sha256"),
            )

            if key in seen:
                continue

            seen.add(key)

            if item.get("port"):
                lines.append(
                    f"  Port: {item['port']}"
                )

            if item.get("subject"):
                lines.append(
                    f"    Subject: {item['subject']}"
                )

            if item.get("issuer"):
                lines.append(
                    f"    Issuer: {item['issuer']}"
                )

            if item.get("tls_version"):
                lines.append(
                    f"    Version: {item['tls_version']}"
                )

            if item.get("sha256"):
                lines.append(
                    f"    SHA256: {item['sha256']}"
                )

            if item.get("names"):
                lines.append(
                    "    SANs: "
                    + ", ".join(
                        map(str, item["names"])
                    )
                )

        return "\n".join(lines)

    def _passive_dns(self, data):
        values = self._unique_values(
            item["value"]
            for item in data["passive_dns"]
        )

        if not values:
            return ""

        lines = ["Passive DNS"]

        for value in values[:20]:
            lines.append(f"  {value}")

        if len(values) > 20:
            lines.append(
                f"  ... and {len(values) - 20} more"
            )

        return "\n".join(lines)

    def _reverse_dns(self, data):
        values = self._unique_values(
            item["value"]
            for item in data["reverse_dns"]
        )

        if not values:
            return ""

        lines = ["Reverse DNS"]

        for value in values:
            lines.append(f"  {value}")

        return "\n".join(lines)

    def _reputation(self, data):
        if not data["reputation"]:
            return ""

        lines = ["Reputation"]

        for item in data["reputation"]:
            source = item["source"]

            if item.get("abuse_confidence") is not None:
                lines.append(
                    f"  {source}: "
                    f"Abuse confidence "
                    f"{item['abuse_confidence']}%"
                )

            if item.get("is_whitelisted") is not None:
                lines.append(
                    f"    Whitelisted: "
                    f"{self._format_value(item['is_whitelisted'])}"
                )

            if item.get("total_reports") is not None:
                lines.append(
                    f"    Reports: "
                    f"{item['total_reports']}"
                )

            if item.get("reputation") is not None:
                lines.append(
                    f"  {source}: "
                    f"Reputation {item['reputation']}"
                )

            if item.get("analysis"):
                analysis = item["analysis"]

                lines.append(
                    "    Analysis: "
                    f"{analysis.get('malicious', 0)} malicious, "
                    f"{analysis.get('suspicious', 0)} suspicious, "
                    f"{analysis.get('harmless', 0)} harmless, "
                    f"{analysis.get('undetected', 0)} undetected"
                )

        return "\n".join(lines)

    def _threats(self, data):
        if not data["threats"]:
            return ""

        lines = ["Threat / CVEs"]

        for item in data["threats"]:
            title = item.get("title") or "Threat context"

            lines.append(
                f"  {title}"
            )

            if item.get("severity"):
                lines.append(
                    f"    Severity: {item['severity']}"
                )

            if item.get("timestamp"):
                lines.append(
                    f"    Observed: {item['timestamp']}"
                )

        return "\n".join(lines)

    def _anonymizer(self, data):
        if not data["anonymizer"]:
            return ""

        lines = ["Anonymizer"]

        for item in data["anonymizer"]:
            lines.append(
                f"  {item['type']}: "
                f"{self._format_value(item['active'])}"
            )

            if item.get("networks"):
                for network in item["networks"]:
                    lines.append(
                        f"    Network: {network}"
                    )

        return "\n".join(lines)

    def _temporal(self, data):
        if not data["temporal"]:
            return ""

        lines = ["Temporal"]

        for item in data["temporal"]:
            if item.get("type") and item.get("date"):
                lines.append(
                    f"  {item['type']}: "
                    f"{item['date']}"
                )

        return "\n".join(lines)

    def _observations(self, data):
        lines = ["Observations"]

        location_conflicts = self._location_conflicts(
            data["location"]
        )

        if location_conflicts:
            lines.append("  Location mismatch:")

            for value, count in location_conflicts:
                lines.append(
                    f"    {value} ({count} sources)"
                )

        return (
            "\n".join(lines)
            if len(lines) > 1
            else ""
        )

    def _sources(self, results, failures):
        lines = ["Sources"]

        for source, _ in results:
            lines.append(f"  {source}")

        if failures:
            lines.append("")
            lines.append("Unavailable")

            for failure in failures:
                lines.append(
                    f"  {failure['tool']}: "
                    f"{failure['error']}"
                )

        return "\n".join(lines)

    @staticmethod
    def _majority(values):
        if not values:
            return None

        return Counter(
            str(value)
            for value in values
        ).most_common(1)[0][0]

    @staticmethod
    def _unique_values(values):
        seen = set()
        result = []

        for value in values:
            if value in (None, ""):
                continue

            if value in seen:
                continue

            seen.add(value)
            result.append(value)

        return result

    @staticmethod
    def _location_conflicts(location):
        values = []

        for item in location:
            value = (
                item.get("city")
                or item.get("region")
                or item.get("country")
                or item.get("country_code")
            )

            if value:
                values.append(value)

        counts = Counter(values)

        if len(counts) <= 1:
            return []

        return counts.most_common()