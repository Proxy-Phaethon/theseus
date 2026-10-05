from collections import Counter

class IPResponder:
    def respond(self, entity, results):
        data = {
            name: result
            for name, result in results
            if isinstance(result, dict)
        }

        sections = []

        self._add_section(
            sections,
            "Identity",
            self._identity(data),
        )

        self._add_section(
            sections,
            "Network / ASN",
            self._network(data),
        )

        self._add_section(
            sections,
            "Location",
            self._location(data),
        )

        self._add_section(
            sections,
            "Cloud / Hosting",
            self._hosting(data),
        )

        self._add_section(
            sections,
            "Exposure",
            self._exposure(data),
        )

        self._add_section(
            sections,
            "Services",
            self._services(data),
        )

        self._add_section(
            sections,
            "TLS",
            self._tls(data),
        )

        self._add_section(
            sections,
            "Passive DNS",
            self._passive_dns(data),
        )

        self._add_section(
            sections,
            "Reverse DNS",
            self._reverse_dns(data),
        )

        self._add_section(
            sections,
            "Reputation",
            self._reputation(data),
        )

        self._add_section(
            sections,
            "Threat Intelligence",
            self._threat_intelligence(data),
        )

        self._add_section(
            sections,
            "Anonymizer",
            self._anonymizer(data),
        )

        self._add_section(
            sections,
            "Observations",
            self._observations(data),
        )

        self._add_section(
            sections,
            "Sources",
            self._sources(results),
        )

        return "\n\n".join(sections)

    def _identity(self, data):
        lines = []

        hostname = self._first_value(
            data,
            [
                ("ShodanTool", "data", "hostnames"),
                ("CensysTool", "result", "dns", "names"),
                ("IPInfoTool", "hostname"),
                ("IPAPITool", "reverse"),
            ],
        )

        if isinstance(hostname, list):
            hostname = hostname[0] if hostname else None

        organization = self._first_value(
            data,
            [
                ("IPInfoTool", "org"),
                ("NetlasTool", "organization"),
                ("IPAPIIsTool", "company", "name"),
                ("IPAPITool", "org"),
            ],
        )

        if organization:
            organization = self._clean_organization(
                organization
            )

        if hostname:
            lines.append(f"  Hostname: {hostname}")

        if organization:
            lines.append(
                f"  Organization: {organization}"
            )

        return lines

    def _network(self, data):
        lines = []

        asns = []
        prefixes = []

        for name, result in data.items():
            asn = self._extract_asn(name, result)
            prefix = self._extract_prefix(name, result)

            if asn:
                asns.append(str(asn))

            if prefix:
                prefixes.append(str(prefix))

        asn = self._consensus(asns)
        prefix = self._consensus(prefixes)

        if asn:
            lines.append(
                f"  ASN: {self._format_asn(asn)}"
            )

        if prefix:
            lines.append(
                f"  Prefix: {prefix}"
            )

        return lines

    def _location(self, data):
        lines = []

        countries = []
        regions = []
        cities = []

        for name, result in data.items():
            country = self._extract_country(
                name,
                result,
            )
            region = self._extract_region(
                name,
                result,
            )
            city = self._extract_city(
                name,
                result,
            )

            if country:
                countries.append(
                    self._normalize_country(country)
                )

            if region:
                regions.append(
                    self._normalize_region(region)
                )

            if city:
                cities.append(
                    self._normalize_city(city)
                )

        country = self._consensus(countries)
        region = self._consensus(regions)
        city = self._consensus(cities)

        if country:
            lines.append(
                f"  Country: {country}"
            )

        if region:
            lines.append(
                f"  Region: {region}"
            )

        if city:
            lines.append(
                f"  City: {city}"
            )

        return lines

    def _hosting(self, data):
        lines = []

        hosting = []
        anycast = []

        for name, result in data.items():
            hosting_value = self._extract_bool(
                name,
                result,
                "hosting",
            )

            anycast_value = self._extract_bool(
                name,
                result,
                "anycast",
            )

            if hosting_value is not None:
                hosting.append(hosting_value)

            if anycast_value is not None:
                anycast.append(anycast_value)

        hosting_value = self._majority(hosting)
        anycast_value = self._majority(anycast)

        if hosting_value is not None:
            lines.append(
                f"  Hosting: {hosting_value}"
            )

        if anycast_value is not None:
            lines.append(
                f"  Anycast: {anycast_value}"
            )

        return lines

    def _exposure(self, data):
        lines = []
        ports = set()

        for name, result in data.items():
            ports.update(
                str(port)
                for port in self._extract_ports(
                    name,
                    result,
                )
            )

        if ports:
            ordered = sorted(
                ports,
                key=lambda value: (
                    int(value)
                    if value.isdigit()
                    else value
                ),
            )

            lines.append(
                f"  Observed ports: {', '.join(ordered)}"
            )

        return lines

    def _services(self, data):
        lines = []
        services = set()

        for name, result in data.items():
            services.update(
                self._extract_services(
                    name,
                    result,
                )
            )

        for service in sorted(services):
            lines.append(f"  {service}")

        return lines

    def _tls(self, data):
        result = data.get("TLSXTool")

        if not isinstance(result, dict):
            return []

        tls_results = result.get("results", [])

        if not isinstance(tls_results, list):
            return []

        lines = []

        for tls in tls_results:
            if not isinstance(tls, dict):
                continue

            port = tls.get("port")

            certificate = tls.get("cert")

            if not isinstance(certificate, dict):
                continue

            parsed = certificate.get("parsed", {})

            if not isinstance(parsed, dict):
                continue

            if port:
                lines.append(f"Port: {port}")

            subject_dn = parsed.get("subject_dn")

            if subject_dn:
                lines.append(f"Subject: {subject_dn}")

            issuer_dn = parsed.get("issuer_dn")

            if issuer_dn:
                lines.append(f"Issuer: {issuer_dn}")

            fingerprint = certificate.get(
                "fingerprint_sha256"
            )

            if fingerprint:
                lines.append(f"SHA256: {fingerprint}")

            subject = parsed.get("subject", {})

            if isinstance(subject, dict):
                sans = subject.get("common_name", [])

                if sans:
                    if isinstance(sans, str):
                        sans = [sans]

                    lines.append(
                        f"SANs: {', '.join(sans)}"
                    )

        return lines

    def _passive_dns(self, data):
        lines = []
        domains = set()

        for name, result in data.items():
            domains.update(
                self._extract_passive_dns(
                    name,
                    result,
                )
            )

        if not domains:
            return lines

        ordered = sorted(domains)
        limit = 20

        for domain in ordered[:limit]:
            lines.append(
                f"  {domain}"
            )

        remaining = len(ordered) - limit

        if remaining > 0:
            lines.append(
                f"  ... and {remaining} more"
            )

        return lines

    def _reverse_dns(self, data):
        lines = []
        values = []

        for name, result in data.items():
            value = self._extract_reverse_dns(
                name,
                result,
            )

            if value:
                values.append(value)

        value = self._consensus(values)

        if value:
            lines.append(
                f"  {value}"
            )

        return lines

    def _reputation(self, data):
        lines = []

        abuse = data.get("AbuseIPDBTool")

        if abuse:
            payload = abuse.get(
                "data",
                abuse,
            )

            score = payload.get(
                "abuseConfidenceScore"
            )

            if score is not None:
                lines.append(
                    f"  AbuseIPDB: "
                    f"Abuse confidence {score}%"
                )

            whitelisted = payload.get(
                "isWhitelisted"
            )

            if whitelisted is not None:
                lines.append(
                    f"    Whitelisted: "
                    f"{whitelisted}"
                )

            reports = payload.get(
                "totalReports"
            )

            if reports is not None:
                lines.append(
                    f"    Reports: {reports}"
                )

        otx = data.get("AlienVaultOTXTool")

        if otx:
            reputation = otx.get(
                "reputation"
            )

            if reputation is not None:
                lines.append(
                    f"  AlienVault OTX: "
                    f"Reputation {reputation}"
                )

        vt = data.get("VirusTotalTool")

        if vt:
            attributes = self._nested(
                vt,
                "data",
                "attributes",
            )

            if isinstance(attributes, dict):
                reputation = attributes.get(
                    "reputation"
                )

                if reputation is not None:
                    lines.append(
                        f"  VirusTotal: "
                        f"Reputation {reputation}"
                    )

                analysis = attributes.get(
                    "last_analysis_stats"
                )

                if isinstance(analysis, dict):
                    lines.append(
                        "    Analysis: "
                        f"{analysis.get('malicious', 0)} "
                        "malicious, "
                        f"{analysis.get('suspicious', 0)} "
                        "suspicious, "
                        f"{analysis.get('harmless', 0)} "
                        "harmless, "
                        f"{analysis.get('undetected', 0)} "
                        "undetected"
                    )

        return lines

    def _threat_intelligence(self, data):
        lines = []

        vt = data.get("VirusTotalTool")

        if not vt:
            return lines

        attributes = self._nested(
            vt,
            "data",
            "attributes",
        )

        if not isinstance(attributes, dict):
            return lines

        contexts = attributes.get(
            "crowdsourced_context",
            [],
        )

        if not isinstance(contexts, list):
            return lines

        for context in contexts:
            if not isinstance(context, dict):
                continue

            source = context.get("source")

            if source != "ThreatFox":
                continue

            date = context.get("date")

            if date:
                lines.append(
                    f"  ThreatFox observation: {date}"
                )

            severity = context.get(
                "severity"
            )

            if severity:
                lines.append(
                    f"    Severity: {severity}"
                )

        return lines

    def _anonymizer(self, data):
        lines = []

        tor = data.get(
            "TorExitListTool"
        )

        if tor:
            value = tor.get(
                "is_tor_exit"
            )

            if value is not None:
                lines.append(
                    f"  Tor: "
                    f"{'Yes' if value else 'No'}"
                )

        vpn = data.get(
            "X4BNetTool"
        )

        if vpn:
            value = vpn.get(
                "is_vpn"
            )

            if value is not None:
                lines.append(
                    f"  VPN: "
                    f"{'Yes' if value else 'No'}"
                )

        return lines

    def _observations(self, data):
        lines = []

        fields = {
            "Country": (
                self._extract_country,
                self._normalize_country,
            ),
            "Region": (
                self._extract_region,
                self._normalize_region,
            ),
            "City": (
                self._extract_city,
                self._normalize_city,
            ),
        }

        for field, (
            extractor,
            normalizer,
        ) in fields.items():
            values = []

            for name, result in data.items():
                value = extractor(
                    name,
                    result,
                )

                if value:
                    values.append(
                        normalizer(value)
                    )

            counts = Counter(values)

            if len(counts) <= 1:
                continue

            lines.append(
                f"  {field} mismatch:"
            )

            for value, count in counts.most_common():
                source_word = (
                    "source"
                    if count == 1
                    else "sources"
                )

                lines.append(
                    f"    {value} "
                    f"({count} {source_word})"
                )

        return lines

    def _sources(self, results):
        lines = []

        for name, result in results:
            if isinstance(result, dict):
                lines.append(
                    f"  {name}"
                )

        return lines

    def _extract_asn(self, name, result):
        if name == "RIPEstatTool":
            asns = self._nested(
                result,
                "data",
                "asns",
            )

            if asns:
                return asns[0]

        if name == "TeamCymruTool":
            records = result.get(
                "results",
                [],
            )

            if records:
                return records[0].get(
                    "asn"
                )

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
            return self._nested(
                result,
                "data",
                "prefix",
            )

        if name == "TeamCymruTool":
            records = result.get(
                "results",
                [],
            )

            if records:
                return records[0].get(
                    "prefix"
                )

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
            return self._nested(
                result,
                "location",
                "country",
            )

        if name == "NetlasTool":
            return result.get("country")

        if name == "CensysTool":
            return self._nested(
                result,
                "result",
                "location",
                "country",
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
            return self._nested(
                result,
                "location",
                "state",
            )

        if name == "NetlasTool":
            return result.get("region")

        if name == "CensysTool":
            return self._nested(
                result,
                "result",
                "location",
                "province",
            )

        return None

    def _extract_city(self, name, result):
        if name == "IPInfoTool":
            return result.get("city")

        if name == "IPAPITool":
            return result.get("city")

        if name == "IPAPIIsTool":
            return self._nested(
                result,
                "location",
                "city",
            )

        if name == "NetlasTool":
            return result.get("city")

        if name == "CensysTool":
            return self._nested(
                result,
                "result",
                "location",
                "city",
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

        return None

    def _extract_ports(self, name, result):
        ports = []

        if name == "CensysTool":
            services = self._nested(
                result,
                "result",
                "services",
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
                "services",
            )

            if isinstance(raw, list):
                for service in raw:
                    port = service.get("port")
                    transport = service.get(
                        "transport_protocol"
                    )
                    service_name = service.get(
                        "service_name"
                    )

                    parts = []

                    if port:
                        parts.append(
                            f"Port {port}"
                        )

                    if transport:
                        parts.append(
                            str(transport)
                        )

                    if service_name:
                        parts.append(
                            str(service_name)
                        )

                    if parts:
                        services.append(
                            " ".join(parts)
                        )

        if name == "ShodanTool":
            raw = result.get("data", [])

            if isinstance(raw, list):
                for item in raw:
                    port = item.get("port")
                    transport = item.get(
                        "transport"
                    )
                    product = item.get(
                        "product"
                    )

                    parts = []

                    if port:
                        parts.append(
                            f"Port {port}"
                        )

                    if transport:
                        parts.append(
                            str(transport)
                        )

                    if product:
                        parts.append(
                            str(product)
                        )

                    if parts:
                        services.append(
                            " ".join(parts)
                        )

        return services

    def _extract_tls(self, name, result):
        tls = []

        if name != "TLSXTool":
            return tls

        raw = result.get(
            "results",
            [],
        )

        if not isinstance(raw, list):
            return tls

        for item in raw:
            certificate = item.get(
                "certificate",
                {},
            )

            tls.append({
                "port": item.get("port"),
                "subject": certificate.get(
                    "subject_dn"
                ),
                "issuer": certificate.get(
                    "issuer_dn"
                ),
                "sha256": self._nested(
                    certificate,
                    "hash",
                    "sha256",
                ),
                "sans": certificate.get(
                    "subject_an",
                    [],
                ) or [],
            })

        return tls

    def _extract_passive_dns(self, name, result):
        domains = set()

        if name == "RobtexTool":
            records = result.get(
                "pas",
                [],
            )

            if isinstance(records, list):
                for record in records:
                    if not isinstance(
                        record,
                        dict,
                    ):
                        continue

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
                "names",
            )

            if isinstance(names, list):
                domains.update(
                    value
                    for value in names
                    if isinstance(
                        value,
                        str,
                    )
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
                "names",
            )

            if names:
                return names[0]

        return None

    @staticmethod
    def _clean_organization(value):
        value = str(value).strip()

        parts = value.split(
            maxsplit=1
        )

        if (
            len(parts) == 2
            and parts[0].upper().startswith("AS")
            and parts[0][2:].isdigit()
        ):
            return parts[1]

        return value

    @staticmethod
    def _normalize_country(value):
        normalized = str(value).strip()

        countries = {
            "US": "United States",
            "USA": "United States",
            "United States of America":
                "United States",
        }

        return countries.get(
            normalized,
            normalized,
        )

    @staticmethod
    def _normalize_region(value):
        return str(value).strip()

    @staticmethod
    def _normalize_city(value):
        return str(value).strip()

    @staticmethod
    def _add_section(
        sections,
        title,
        lines,
    ):
        if not lines:
            return

        sections.append(
            "\n".join(
                [title, *lines]
            )
        )

    @staticmethod
    def _nested(value, *keys):
        for key in keys:
            if not isinstance(
                value,
                dict,
            ):
                return None

            value = value.get(key)

        return value

    @staticmethod
    def _first_value(data, paths):
        for name, *keys in paths:
            result = data.get(name)

            if result is None:
                continue

            value = IPResponder._nested(
                result,
                *keys,
            )

            if value:
                return value

        return None

    @staticmethod
    def _consensus(values):
        values = [
            str(value)
            for value in values
            if value not in (
                None,
                "",
            )
        ]

        if not values:
            return None

        return Counter(
            values
        ).most_common(1)[0][0]

    @staticmethod
    def _majority(values):
        if not values:
            return None

        return Counter(
            values
        ).most_common(1)[0][0]

    @staticmethod
    def _format_asn(value):
        value = str(value)

        if value.upper().startswith("AS"):
            return value

        if value.isdigit():
            return f"AS{value}"

        return value