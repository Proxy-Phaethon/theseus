from collections import Counter

class IPResponder:
    def respond(self, entity, results):
        data = {
            name: result
            for name, result in results
            if isinstance(result, dict)
        }

        lines = []

        lines.append("Identity")
        self._identity(lines, data)

        lines.append("\nNetwork / ASN")
        self._network(lines, data)

        lines.append("\nLocation")
        self._location(lines, data)

        lines.append("\nCloud / Hosting")
        self._hosting(lines, data)

        lines.append("\nExposure")
        self._exposure(lines, data)

        lines.append("\nServices")
        self._services(lines, data)

        lines.append("\nTLS")
        self._tls(lines, data)

        lines.append("\nPassive DNS")
        self._passive_dns(lines, data)

        lines.append("\nReverse DNS")
        self._reverse_dns(lines, data)

        lines.append("\nReputation")
        self._reputation(lines, data)

        lines.append("\nThreat Intelligence")
        self._threat_intelligence(lines, data)

        lines.append("\nAnonymizer")
        self._anonymizer(lines, data)

        lines.append("\nObservations")
        self._observations(lines, data)

        lines.append("\nSources")
        self._sources(lines, data, results)

        return "\n".join(lines)

    def _identity(self, lines, data):
        hostname = self._first_value(
            data,
            [
                ("ShodanTool", "data", "hostnames"),
                ("CensysTool", "result", "dns", "names"),
                ("IPInfoTool", "hostname"),
                ("IPAPITool", "reverse"),
            ],
        )

        organization = self._first_value(
            data,
            [
                ("IPInfoTool", "org"),
                ("NetlasTool", "organization"),
                ("IPAPIIsTool", "company", "name"),
                ("IPAPITool", "org"),
                ("RobtexTool", "asname"),
            ],
        )

        if hostname:
            if isinstance(hostname, list):
                hostname = hostname[0] if hostname else None

            if hostname:
                lines.append(f"  Hostname: {hostname}")

        if organization:
            lines.append(f"  Organization: {organization}")

    def _network(self, lines, data):
        asn_values = []
        prefix_values = []

        for name, result in data.items():
            asn = self._extract_asn(name, result)
            prefix = self._extract_prefix(name, result)

            if asn:
                asn_values.append(str(asn))

            if prefix:
                prefix_values.append(str(prefix))

        asn = self._consensus(asn_values)
        prefix = self._consensus(prefix_values)

        if asn:
            lines.append(f"  ASN: {self._format_asn(asn)}")

        if prefix:
            lines.append(f"  Prefix: {prefix}")

    def _location(self, lines, data):
        countries = []
        regions = []
        cities = []

        for name, result in data.items():
            country = self._extract_country(name, result)
            region = self._extract_region(name, result)
            city = self._extract_city(name, result)

            if country:
                countries.append(country)

            if region:
                regions.append(region)

            if city:
                cities.append(city)

        country = self._consensus(countries)
        region = self._consensus(regions)
        city = self._consensus(cities)

        if country:
            lines.append(f"  Country: {country}")

        if region:
            lines.append(f"  Region: {region}")

        if city:
            lines.append(f"  City: {city}")

    def _hosting(self, lines, data):
        hosting_values = []
        anycast_values = []

        for name, result in data.items():
            hosting = self._extract_bool(name, result, "hosting")
            anycast = self._extract_bool(name, result, "anycast")

            if hosting is not None:
                hosting_values.append(hosting)

            if anycast is not None:
                anycast_values.append(anycast)

        hosting = self._majority(hosting_values)
        anycast = self._majority(anycast_values)

        if hosting is not None:
            lines.append(f"  Hosting: {hosting}")

        if anycast is not None:
            lines.append(f"  Anycast: {anycast}")

    def _exposure(self, lines, data):
        ports = set()

        for name, result in data.items():
            for port in self._extract_ports(name, result):
                ports.add(str(port))

        if ports:
            ordered = sorted(
                ports,
                key=lambda value: int(value)
                if value.isdigit()
                else value
            )

            lines.append(
                f"  Observed ports: {', '.join(ordered)}"
            )

    def _services(self, lines, data):
        services = set()

        for name, result in data.items():
            for service in self._extract_services(name, result):
                services.add(service)

        for service in sorted(services):
            lines.append(f"  {service}")

    def _tls(self, lines, data):
        certificates = {}

        for name, result in data.items():
            for cert in self._extract_tls(name, result):
                fingerprint = cert.get("sha256")

                if not fingerprint:
                    fingerprint = (
                        cert.get("subject"),
                        cert.get("issuer"),
                    )

                if fingerprint not in certificates:
                    certificates[fingerprint] = {
                        "cert": cert,
                        "sources": set(),
                        "ports": set(),
                    }

                certificates[fingerprint]["sources"].add(name)

                port = cert.get("port")
                if port:
                    certificates[fingerprint]["ports"].add(str(port))

        for entry in certificates.values():
            cert = entry["cert"]
            ports = sorted(entry["ports"])

            if ports:
                lines.append(
                    f"  Port: {', '.join(ports)}"
                )

            if cert.get("subject"):
                lines.append(
                    f"    Subject: {cert['subject']}"
                )

            if cert.get("issuer"):
                lines.append(
                    f"    Issuer: {cert['issuer']}"
                )

            if cert.get("sha256"):
                lines.append(
                    f"    SHA256: {cert['sha256']}"
                )

            sans = cert.get("sans", [])

            if sans:
                lines.append(
                    f"    SANs: {', '.join(sans)}"
                )

    def _passive_dns(self, lines, data):
        domains = set()

        for name, result in data.items():
            domains.update(
                self._extract_passive_dns(name, result)
            )

        if not domains:
            return

        ordered = sorted(domains)

        limit = 20

        for domain in ordered[:limit]:
            lines.append(f"  {domain}")

        remaining = len(ordered) - limit

        if remaining > 0:
            lines.append(
                f"  ... and {remaining} more"
            )

    def _reverse_dns(self, lines, data):
        values = []

        for name, result in data.items():
            value = self._extract_reverse_dns(name, result)

            if value:
                values.append(value)

        value = self._consensus(values)

        if value:
            lines.append(f"  {value}")

    def _reputation(self, lines, data):
        abuse = data.get("AbuseIPDBTool")

        if abuse:
            payload = abuse.get("data", abuse)

            score = payload.get("abuseConfidenceScore")

            if score is not None:
                lines.append(
                    f"  AbuseIPDB: Abuse confidence {score}%"
                )

            if payload.get("isWhitelisted") is not None:
                lines.append(
                    f"    Whitelisted: "
                    f"{payload['isWhitelisted']}"
                )

            reports = payload.get("totalReports")

            if reports is not None:
                lines.append(
                    f"    Reports: {reports}"
                )

        otx = data.get("AlienVaultOTXTool")

        if otx:
            reputation = self._nested(
                otx,
                "reputation"
            )

            if reputation is not None:
                lines.append(
                    f"  AlienVault OTX: Reputation {reputation}"
                )

        vt = data.get("VirusTotalTool")

        if vt:
            attributes = self._nested(
                vt,
                "data",
                "attributes"
            )

            if isinstance(attributes, dict):
                reputation = attributes.get("reputation")

                if reputation is not None:
                    lines.append(
                        f"  VirusTotal: Reputation {reputation}"
                    )

                analysis = attributes.get(
                    "last_analysis_stats"
                )

                if isinstance(analysis, dict):
                    lines.append(
                        "    Analysis: "
                        f"{analysis.get('malicious', 0)} malicious, "
                        f"{analysis.get('suspicious', 0)} suspicious, "
                        f"{analysis.get('harmless', 0)} harmless, "
                        f"{analysis.get('undetected', 0)} undetected"
                    )

    def _threat_intelligence(self, lines, data):
        vt = data.get("VirusTotalTool")

        if not vt:
            return

        attributes = self._nested(
            vt,
            "data",
            "attributes"
        )

        if not isinstance(attributes, dict):
            return

        contexts = attributes.get("crowdsourced_context", [])

        if not isinstance(contexts, list):
            return

        for context in contexts:
            if not isinstance(context, dict):
                continue

            if context.get("source") == "ThreatFox":
                date = context.get("date")

                if date:
                    lines.append(
                        f"  ThreatFox observation: {date}"
                    )

                severity = context.get("severity")

                if severity:
                    lines.append(
                        f"    Severity: {severity}"
                    )

    def _anonymizer(self, lines, data):
        tor = data.get("TorExitListTool")

        if tor:
            value = tor.get("is_tor_exit")

            if value is not None:
                lines.append(
                    f"  Tor: {'Yes' if value else 'No'}"
                )

        vpn = data.get("X4BNetTool")

        if vpn:
            value = vpn.get("is_vpn")

            if value is not None:
                lines.append(
                    f"  VPN: {'Yes' if value else 'No'}"
                )

    def _observations(self, lines, data):
        found = False

        location_groups = {
            "Country": self._collect_field(
                data,
                self._extract_country,
            ),
            "Region": self._collect_field(
                data,
                self._extract_region,
            ),
            "City": self._collect_field(
                data,
                self._extract_city,
            ),
        }

        for field, values in location_groups.items():
            counts = Counter(values)

            if len(counts) <= 1:
                continue

            if not found:
                found = True

            lines.append(
                f"  {field} mismatch:"
            )

            for value, count in counts.most_common():
                lines.append(
                    f"    {value} ({count} sources)"
                )

        if not found:
            lines.append("  None")

    def _sources(self, lines, data, results):
        successful = []

        for name, result in results:
            if isinstance(result, dict):
                successful.append(name)

        for name in successful:
            lines.append(f"  {name}")

    def _extract_asn(self, name, result):
        if name == "RIPEstatTool":
            data = result.get("data", {})
            asns = data.get("asns", [])

            if asns:
                return asns[0]

        if name == "TeamCymruTool":
            records = result.get("results", [])

            if records:
                return records[0].get("asn")

        if name == "IPInfoTool":
            value = result.get("org")

            if isinstance(value, str):
                return value.split()[0]

        if name == "IPAPIIsTool":
            value = result.get("asn")

            if isinstance(value, dict):
                return value.get("asn")

            return value

        if name == "IPAPITool":
            value = result.get("as")

            if isinstance(value, str):
                return value.split()[0]

        if name == "NetlasTool":
            value = result.get("asn")

            if isinstance(value, dict):
                return value.get("asn")

            return value

        if name == "RobtexTool":
            value = result.get("as")

            if isinstance(value, dict):
                return value.get("asn")

            return value

        return None

    def _extract_prefix(self, name, result):
        if name == "RIPEstatTool":
            return result.get("data", {}).get("prefix")

        if name == "TeamCymruTool":
            records = result.get("results", [])

            if records:
                return records[0].get("prefix")

        if name == "NetlasTool":
            return result.get("route")

        if name == "RobtexTool":
            return result.get("route")

        return None

    def _extract_country(self, name, result):
        if name == "IPInfoTool":
            return result.get("country")

        if name == "IPAPITool":
            return result.get("country")

        if name == "IPAPIIsTool":
            return result.get("location", {}).get("country")

        if name == "NetlasTool":
            return result.get("country")

        if name == "CensysTool":
            return self._nested(
                result,
                "result",
                "location",
                "country"
            )

        if name == "RobtexTool":
            return result.get("country")

        return None

    def _extract_region(self, name, result):
        if name == "IPInfoTool":
            return result.get("region")

        if name == "IPAPITool":
            return result.get("regionName")

        if name == "IPAPIIsTool":
            return result.get("location", {}).get("state")

        if name == "NetlasTool":
            return result.get("region")

        if name == "CensysTool":
            return self._nested(
                result,
                "result",
                "location",
                "province"
            )

        return None

    def _extract_city(self, name, result):
        if name == "IPInfoTool":
            return result.get("city")

        if name == "IPAPITool":
            return result.get("city")

        if name == "IPAPIIsTool":
            return result.get("location", {}).get("city")

        if name == "NetlasTool":
            return result.get("city")

        if name == "CensysTool":
            return self._nested(
                result,
                "result",
                "location",
                "city"
            )

        if name == "RobtexTool":
            return result.get("city")

        return None

    def _extract_bool(self, name, result, field):
        if name == "IPInfoTool":
            if field == "anycast":
                return result.get("anycast")

        if name == "IPAPITool":
            if field == "hosting":
                return result.get("hosting")

        if name == "NetlasTool":
            if field == "hosting":
                return result.get("hosting")

        if name == "IPAPIIsTool":
            if field == "hosting":
                return result.get("is_abuser")

        return None

    def _extract_ports(self, name, result):
        ports = []

        if name == "CensysTool":
            services = self._nested(
                result,
                "result",
                "services"
            )

            if isinstance(services, list):
                for service in services:
                    port = service.get("port")

                    if port:
                        ports.append(port)

        if name == "ShodanTool":
            raw = result.get("ports", [])

            if isinstance(raw, list):
                ports.extend(raw)

        return ports

    def _extract_services(self, name, result):
        services = []

        if name == "CensysTool":
            raw = self._nested(
                result,
                "result",
                "services"
            )

            if isinstance(raw, list):
                for service in raw:
                    port = service.get("port")
                    transport = service.get("transport_protocol")
                    name_value = service.get("service_name")

                    parts = []

                    if port:
                        parts.append(f"Port {port}")

                    if transport:
                        parts.append(str(transport))

                    if name_value:
                        parts.append(str(name_value))

                    if parts:
                        services.append(" ".join(parts))

        if name == "ShodanTool":
            raw = result.get("data", [])

            if isinstance(raw, list):
                for item in raw:
                    port = item.get("port")
                    transport = item.get("transport")
                    product = item.get("product")

                    parts = []

                    if port:
                        parts.append(f"Port {port}")

                    if transport:
                        parts.append(str(transport))

                    if product:
                        parts.append(str(product))

                    if parts:
                        services.append(" ".join(parts))

        return services

    def _extract_tls(self, name, result):
        tls = []

        if name == "TLSXTool":
            raw = result.get("results", [])

            if isinstance(raw, list):
                for item in raw:
                    tls.append({
                        "port": item.get("port"),
                        "subject": self._nested(
                            item,
                            "certificate",
                            "subject_dn"
                        ),
                        "issuer": self._nested(
                            item,
                            "certificate",
                            "issuer_dn"
                        ),
                        "sha256": self._nested(
                            item,
                            "certificate",
                            "hash",
                            "sha256"
                        ),
                        "sans": self._nested(
                            item,
                            "certificate",
                            "subject_an"
                        ) or [],
                    })

        return tls

    def _extract_passive_dns(self, name, result):
        domains = set()

        if name == "RobtexTool":
            records = result.get("pas", [])

            if isinstance(records, list):
                for record in records:
                    if isinstance(record, dict):
                        hostname = (
                            record.get("hostname")
                            or record.get("name")
                        )

                        if hostname:
                            domains.add(hostname)

        if name == "CensysTool":
            names = self._nested(
                result,
                "result",
                "dns",
                "names"
            )

            if isinstance(names, list):
                domains.update(
                    name
                    for name in names
                    if isinstance(name, str)
                )

        return domains

    def _extract_reverse_dns(self, name, result):
        if name == "IPInfoTool":
            return result.get("hostname")

        if name == "IPAPITool":
            return result.get("reverse")

        if name == "CensysTool":
            names = self._nested(
                result,
                "result",
                "dns",
                "names"
            )

            if names:
                return names[0]

        return None

    @staticmethod
    def _nested(value, *keys):
        for key in keys:
            if not isinstance(value, dict):
                return None

            value = value.get(key)

        return value

    @staticmethod
    def _first_value(data, paths):
        for name, *keys in paths:
            result = data.get(name)

            if result is None:
                continue

            value = IPResponder._nested(result, *keys)

            if value:
                return value

        return None

    @staticmethod
    def _consensus(values):
        values = [
            str(value)
            for value in values
            if value not in (None, "")
        ]

        if not values:
            return None

        return Counter(values).most_common(1)[0][0]

    @staticmethod
    def _majority(values):
        if not values:
            return None

        counts = Counter(values)
        return counts.most_common(1)[0][0]

    @staticmethod
    def _collect_field(data, extractor):
        values = []

        for name, result in data.items():
            value = extractor(name, result)

            if value not in (None, ""):
                values.append(str(value))

        return values

    @staticmethod
    def _format_asn(value):
        value = str(value)

        if value.upper().startswith("AS"):
            return value

        if value.isdigit():
            return f"AS{value}"

        return value