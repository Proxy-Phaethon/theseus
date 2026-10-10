from datetime import datetime, timezone
import ipaddress
import re

class DomainResponder:
    """Render domain collector results without modifying the raw results."""

    SUBDOMAIN_PREVIEW_LIMIT = 30
    CERTIFICATE_NAME_LIMIT = 30
    GENERIC_OUTPUT_LIMIT = 3000

    def respond(self, entity, results):
        self.data = self._results_to_dict(results)
        target = getattr(entity, "value", None) or getattr(entity, "target", None)
        self.subdomains = self.get_subdomains(self.data, target=target)
        sections = []

        section_builders = (
            ("Identity & Registration", lambda: self._identity(entity, self.data)),
            ("DNS & Hosting", lambda: self._dns(self.data)),
            ("Subdomains", lambda: self._subdomains(self.subdomains)),
            ("Email Security", lambda: self._email_security(self.data)),
            ("Certificates", lambda: self._certificates(self.data)),
            ("Lookalikes", lambda: self._lookalikes(self.data)),
            ("Takeover Risk", lambda: self._takeover(self.data)),
            ("Web Presence & Technology", lambda: self._web_presence(self.data)),
            ("Tracking-ID Pivots", lambda: self._tracking_ids(self.data)),
            ("Passive DNS", lambda: self._passive_dns(self.data)),
            ("Reputation & Threat Intelligence", lambda: self._reputation(self.data)),
        )

        for title, build in section_builders:
            self._add_section(sections, title, build())
        return "\n\n".join(sections)

    def get_subdomains(self, results=None, target=None):
        """Return every unique subdomain for optional display by the CLI."""
        data = self._results_to_dict(results) if results is not None else getattr(self, "data", {})
        target = (str(target).strip().lower().rstrip(".") if target else None) or self._target_from_data(data)
        found = {}

        for name, result in data.items():
            normalized = self._normalize_name(name)
            if not any(term in normalized for term in ("subfinder", "assetfinder", "sublist3r", "amass", "findomain", "subdomain")):
                continue
            source = name
            for value in self._extract_strings(result):
                hostname = value.strip().lower().rstrip(".")
                hostname = hostname.removeprefix("*.")
                if not self._is_hostname(hostname):
                    continue
                if target and hostname == target.lower().rstrip("."):
                    continue
                if target and not hostname.endswith("." + target.lower().rstrip(".")):
                    continue
                found.setdefault(hostname, set()).add(source)

        return [
            {"hostname": hostname, "sources": sorted(sources)}
            for hostname, sources in sorted(found.items())
        ]

    @staticmethod
    def _results_to_dict(results):
        if isinstance(results, dict):
            return {str(name): value for name, value in results.items()}
        data = {}
        if results is None:
            return data
        try:
            for item in results:
                if isinstance(item, (tuple, list)) and len(item) >= 2:
                    data[str(item[0])] = item[1]
        except TypeError:
            pass
        return data

    @staticmethod
    def _normalize_name(name):
        return re.sub(r"[^a-z0-9]", "", str(name).lower())

    @staticmethod
    def _add_section(sections, title, lines):
        if lines:
            sections.append(title + "\n" + "\n".join(lines))

    @classmethod
    def _tool(cls, data, *terms):
        for name, result in data.items():
            normalized = cls._normalize_name(name)
            if any(term in normalized for term in terms):
                return result
        return None

    @staticmethod
    def _get(obj, *path):
        for key in path:
            if not isinstance(obj, dict) or key not in obj:
                return None
            obj = obj[key]
        return obj

    @staticmethod
    def _clean(value):
        if value is None:
            return None
        if isinstance(value, str):
            value = value.strip()
            return value or None
        if isinstance(value, (int, float, bool)):
            return str(value)
        return None

    @classmethod
    def _list(cls, value):
        if value is None:
            return []
        if isinstance(value, str):
            return [line.strip() for line in value.splitlines() if line.strip()]
        if isinstance(value, (list, tuple, set)):
            output = []
            for item in value:
                if item is None:
                    continue
                if isinstance(item, (str, int, float)):
                    text = str(item).strip()
                    if text:
                        output.append(text)
            return output
        if isinstance(value, (int, float)):
            return [str(value)]
        return []

    @classmethod
    def _extract_strings(cls, value):
        """Extract hostname-like strings from common collector response shapes."""
        if isinstance(value, str):
            return value.splitlines()
        if isinstance(value, (list, tuple, set)):
            output = []
            for item in value:
                if isinstance(item, str):
                    output.extend(item.splitlines())
                elif isinstance(item, dict):
                    for key in ("host", "hostname", "domain", "subdomain", "name", "url"):
                        candidate = item.get(key)
                        if isinstance(candidate, str):
                            output.append(candidate)
            return output
        if isinstance(value, dict):
            output = []
            for key in ("subdomains", "hosts", "results", "data"):
                if key in value:
                    output.extend(cls._extract_strings(value[key]))
            if not output:
                for key, item in value.items():
                    if isinstance(key, str) and cls._is_hostname(key):
                        output.append(key)
                    if isinstance(item, str) and cls._is_hostname(item.strip()):
                        output.append(item.strip())
            return output
        return []

    @staticmethod
    def _is_hostname(value):
        if not isinstance(value, str) or not value or len(value) > 253:
            return False
        value = value.strip().rstrip(".")
        if not value or any(char.isspace() for char in value):
            return False
        value = value.removeprefix("*.")
        if "://" in value or "/" in value or value.startswith(("[", "error:", "warning:")):
            return False
        try:
            ipaddress.ip_address(value)
            return False
        except ValueError:
            pass
        labels = value.split(".")
        if len(labels) < 2:
            return False
        return all(
            label and len(label) <= 63
            and re.fullmatch(r"[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?", label)
            for label in labels
        )

    @staticmethod
    def _target_from_data(data):
        for name, result in data.items():
            if "domain" in DomainResponder._normalize_name(name) and isinstance(result, dict):
                for key in ("domain", "ldhName", "ldh_name", "target"):
                    value = result.get(key)
                    if isinstance(value, str) and DomainResponder._is_hostname(value):
                        return value.rstrip(".")
        return None

    @staticmethod
    def _format_date(value):
        if value is None or value == "":
            return None
        if isinstance(value, (int, float)):
            try:
                return datetime.fromtimestamp(value, tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
            except (OverflowError, OSError, ValueError):
                return None
        value = str(value).strip()
        if not value:
            return None
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            if parsed.tzinfo:
                return parsed.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
            return parsed.strftime("%Y-%m-%d %H:%M")
        except ValueError:
            return value

    @staticmethod
    def _first_regex(text, patterns):
        if not isinstance(text, str):
            return None
        for pattern in patterns:
            match = re.search(pattern, text, re.IGNORECASE | re.MULTILINE)
            if match:
                value = match.group(1).strip()
                if value and value.lower() not in {"redacted", "not disclosed", "n/a", "none"}:
                    return value
        return None

    @classmethod
    def _vt_attributes(cls, data):
        vt = cls._tool(data, "virustotal", "vttool")
        return cls._get(vt, "data", "attributes") if isinstance(vt, dict) else None

    def _identity(self, entity, data):
        lines = []
        target = getattr(entity, "value", None) or getattr(entity, "target", None)
        if target:
            lines.append(f"  Domain: {target}")

        whois = self._tool(data, "whois")
        whois = whois if isinstance(whois, str) else ""
        rdap = self._tool(data, "rdap")
        attrs = self._vt_attributes(data)
        vt_whois = self._get(attrs, "whois")
        vt_whois = vt_whois if isinstance(vt_whois, str) else ""

        fields = (
            ("Registrar", [r"^Registrar:\s*(.+)$", r"^Registrar Name:\s*(.+)$"]),
            ("Created", [r"^(?:Creation Date|Created On|Create date):\s*(.+)$"]),
            ("Updated", [r"^(?:Updated Date|Last Updated On|Update date):\s*(.+)$"]),
            ("Expires", [r"^(?:Registry Expiry Date|Registrar Registration Expiration Date|Expiry date):\s*(.+)$"]),
            ("Registrant organization", [r"^Registrant Organization:\s*(.+)$", r"^Registrant company:\s*(.+)$"]),
            ("Registrant country", [r"^Registrant Country:\s*(.+)$", r"^Registrant country:\s*(.+)$"]),
        )
        for label, patterns in fields:
            value = self._first_regex(whois, patterns) or self._first_regex(vt_whois, patterns)
            if value:
                lines.append(f"  {label}: {value}")

        if isinstance(rdap, dict):
            domain_name = rdap.get("ldhName") or rdap.get("ldh_name")
            if domain_name and not target:
                lines.insert(0, f"  Domain: {domain_name}")
            statuses = self._list(rdap.get("status"))
            if statuses:
                lines.append("  Status: " + ", ".join(dict.fromkeys(statuses)))
            secure_dns = rdap.get("secureDNS") or rdap.get("secure_dns")
            if isinstance(secure_dns, dict):
                signed = secure_dns.get("delegationSigned", secure_dns.get("delegation_signed"))
                if signed is not None:
                    lines.append(f"  DNSSEC: {'signed' if signed else 'unsigned'}")

        dnssec = self._first_regex(whois, [r"^DNSSEC:\s*(.+)$"]) or self._first_regex(vt_whois, [r"^DNSSEC:\s*(.+)$"])
        if dnssec and not any(line.startswith("  DNSSEC:") for line in lines):
            lines.append(f"  DNSSEC: {dnssec}")
        check = self._tool(data, "checkdmarc")
        if isinstance(check, dict) and check.get("dnssec") is not None and not any(line.startswith("  DNSSEC:") for line in lines):
            lines.append(f"  DNSSEC: {'signed' if check['dnssec'] else 'unsigned'}")
        return lines

    @staticmethod
    def _normalize_dns_value(record_type, value):
        value = str(value).strip().strip('"').strip()
        if not value:
            return "", ""
        kind = str(record_type).upper().strip()
        if kind in {"A", "AAAA"}:
            try:
                parsed = ipaddress.ip_address(value)
                return str(parsed), str(parsed)
            except ValueError:
                pass
        if kind in {"NS", "CNAME", "PTR"}:
            display = value.rstrip(".")
            return display, display.lower()
        if kind == "MX":
            fields = value.split()
            if len(fields) >= 2 and fields[0].isdigit():
                display = f"{fields[0]} {fields[1].rstrip('.')}"
            else:
                display = value.rstrip(".")
            return display, display.lower()
        if kind == "TXT":
            display = re.sub(r'"\s+"', "", value)
            return display, display.lower()
        display = " ".join(value.split())
        return display, display.lower()

    def _dns(self, data):
        records = {}

        def add(record_type, value, source):
            if not record_type or value is None:
                return
            kind = str(record_type).upper().strip()
            display, normalized = self._normalize_dns_value(kind, value)
            if not display:
                return
            key = (kind, normalized)
            if key not in records:
                records[key] = {"type": kind, "value": display, "sources": set()}
            records[key]["sources"].add(source)

        for name, result in data.items():
            normalized_name = self._normalize_name(name)
            if "dig" in normalized_name and isinstance(result, dict):
                for record_type, raw in result.items():
                    kind = str(record_type).upper()
                    if kind not in {"A", "AAAA", "CNAME", "NS", "MX", "SOA", "CAA", "SRV", "TXT", "PTR"}:
                        continue
                    for raw_line in self._list(raw):
                        fields = raw_line.split()
                        if "IN" in fields:
                            index = fields.index("IN")
                            if len(fields) > index + 2:
                                raw_line = " ".join(fields[index + 2:])
                        add(kind, raw_line, name)
            elif "dnsx" in normalized_name and isinstance(result, str):
                for raw_line in result.splitlines():
                    match = re.match(r"\S+\s+\[([^]]+)\]\s+\[(.*)]\s*$", raw_line.strip())
                    if match:
                        add(match.group(1), match.group(2), name)
            elif "checkdmarc" in normalized_name and isinstance(result, dict):
                for key, kind in (("ns", "NS"), ("mx", "MX")):
                    block = result.get(key)
                    if not isinstance(block, dict):
                        continue
                    values = block.get("hostnames") if key == "ns" else block.get("hosts")
                    for item in values or []:
                        if isinstance(item, dict):
                            if kind == "MX":
                                host = item.get("hostname") or item.get("exchange")
                                preference = item.get("preference") or item.get("priority")
                                value = f"{preference} {host}" if host and preference is not None else host
                            else:
                                value = item.get("hostname") or item.get("name")
                        else:
                            value = item
                        add(kind, value, name)

        attrs = self._vt_attributes(data)
        vt_records = self._get(attrs, "last_dns_records")
        if isinstance(vt_records, list):
            for record in vt_records:
                if not isinstance(record, dict):
                    continue
                kind = record.get("type")
                value = record.get("value")
                if not kind or value is None:
                    continue
                kind = str(kind).upper()
                if kind == "SOA":
                    parts = [record.get(key) for key in ("value", "rname", "serial", "refresh", "retry", "expire", "minimum")]
                    value = " ".join(str(part) for part in parts if part is not None)
                elif kind == "CAA" and record.get("tag"):
                    value = f"{record.get('flag', 0)} {record['tag']} {value}"
                add(kind, value, "VirusTotal")

        if not records:
            return []
        lines = []
        order = {kind: index for index, kind in enumerate(("A", "AAAA", "CNAME", "NS", "MX", "SOA", "CAA", "SRV", "TXT", "PTR"))}
        for record in sorted(records.values(), key=lambda item: (order.get(item["type"], 99), item["value"].lower())):
            source_text = ", ".join(sorted(record["sources"]))
            lines.append(f"  {record['type']}: {record['value']} [{source_text}]")
        return lines

    def _subdomains(self, subdomains):
        if not subdomains:
            return []
        total = len(subdomains)
        lines = [f"  Total unique subdomains: {total}"]
        for item in subdomains[: self.SUBDOMAIN_PREVIEW_LIMIT]:
            sources = ", ".join(item["sources"])
            lines.append(f"  {item['hostname']} [{sources}]")
        remaining = total - min(total, self.SUBDOMAIN_PREVIEW_LIMIT)
        if remaining:
            lines.append(f"  {remaining} more not shown. The CLI can offer to print the complete list at the end of the lookup.")
        return lines

    def _email_security(self, data):
        check = self._tool(data, "checkdmarc")
        if not isinstance(check, dict):
            return []
        lines = []
        fields = (("mx", "MX"), ("spf", "SPF"), ("dmarc", "DMARC"), ("mta_sts", "MTA-STS"), ("smtp_tls_reporting", "SMTP TLS Reporting"), ("bimi", "BIMI"))
        for key, label in fields:
            block = check.get(key)
            if not isinstance(block, dict):
                continue
            record = block.get("record")
            valid = block.get("valid")
            if key == "mx":
                hosts = block.get("hosts")
                if hosts:
                    formatted = []
                    for host in hosts:
                        if isinstance(host, dict):
                            formatted.append(str(host.get("hostname") or host.get("exchange") or host))
                        else:
                            formatted.append(str(host))
                    lines.append(f"  MX: {', '.join(dict.fromkeys(formatted))}")
                elif "hosts" in block:
                    lines.append("  MX: no MX hosts returned")
            elif record:
                lines.append(f"  {label}: {record}" + (f" (valid: {valid})" if valid is not None else ""))
            elif valid is not None:
                lines.append(f"  {label}: {'valid' if valid else 'not detected or invalid'}")
            if block.get("error"):
                lines.append(f"    Note: {block['error']}")
            for warning in self._list(block.get("warnings")):
                lines.append(f"    Warning: {warning}")
        for warning in self._list(check.get("warnings")):
            lines.append(f"  Warning: {warning}")
        return lines

    def _certificates(self, data):
        attrs = self._vt_attributes(data)
        cert = self._get(attrs, "last_https_certificate")
        if not isinstance(cert, dict):
            return []
        lines = []
        subject = self._get(cert, "subject", "CN")
        issuer = self._get(cert, "issuer", "O") or self._get(cert, "issuer", "CN")
        validity = cert.get("validity") if isinstance(cert.get("validity"), dict) else {}
        if subject:
            lines.append(f"  Subject: {subject}")
        if issuer:
            lines.append(f"  Issuer: {issuer}")
        if validity.get("not_before"):
            lines.append(f"  Valid from: {validity['not_before']}")
        if validity.get("not_after"):
            lines.append(f"  Valid until: {validity['not_after']}")
        sans = self._get(cert, "extensions", "subject_alternative_name")
        if isinstance(sans, (list, tuple, set)):
            unique = sorted({str(name).strip() for name in sans if str(name).strip()})
            if unique:
                lines.append(f"  Subject alternative names ({len(unique)}): " + ", ".join(unique[:self.CERTIFICATE_NAME_LIMIT]))
                if len(unique) > self.CERTIFICATE_NAME_LIMIT:
                    lines.append(f"  ... and {len(unique) - self.CERTIFICATE_NAME_LIMIT} more SAN entries")
        thumbprint = cert.get("thumbprint_sha256")
        if thumbprint:
            lines.append(f"  SHA-256 fingerprint: {thumbprint}")
        return lines

    def _lookalikes(self, data):
        result = self._tool(data, "lookalike", "typosquat", "dnstwist")
        if result is None:
            return []
        lines = []
        if isinstance(result, str):
            return [f"  {line}" for line in result.splitlines() if line.strip()]
        if isinstance(result, list):
            candidates = []
            for item in result:
                if isinstance(item, str) and item.strip():
                    candidates.append(item.strip())
                elif isinstance(item, dict):
                    name = item.get("domain") or item.get("hostname") or item.get("name")
                    if name:
                        candidates.append(str(name))
            if candidates:
                unique = sorted(set(candidates), key=str.lower)
                lines.append(f"  Candidate domains: {len(unique)}")
                lines.extend(f"  {item}" for item in unique[:100])
                if len(unique) > 100:
                    lines.append(f"  ... and {len(unique) - 100} more candidates")
        elif isinstance(result, dict) and result:
            lines.append("  Collector output: " + repr(result)[:self.GENERIC_OUTPUT_LIMIT])
        return lines

    def _takeover(self, data):
        result = self._tool(data, "takeover", "subjack", "nuclei")
        if result is None or result == [] or result == {} or result == "":
            return []
        if isinstance(result, str):
            return [f"  {line}" for line in result.splitlines() if line.strip()]
        return ["  Collector output: " + repr(result)[:self.GENERIC_OUTPUT_LIMIT]]

    def _generic_collector_section(self, data, terms, limit=GENERIC_OUTPUT_LIMIT):
        lines = []
        for name, result in data.items():
            normalized = self._normalize_name(name)
            if not any(term in normalized for term in terms) or not result:
                continue
            if isinstance(result, str):
                lines.extend(f"  {line}" for line in result.splitlines() if line.strip())
            elif isinstance(result, (dict, list, tuple)):
                rendered = repr(result)
                lines.append(f"  {name}: {rendered[:limit]}")
                if len(rendered) > limit:
                    lines.append(f"    Output truncated for display ({len(rendered) - limit} characters omitted). Raw collector results are unchanged.")
        return lines

    def _web_presence(self, data):
        lines = []
        attrs = self._vt_attributes(data)
        categories = attrs.get("categories") if isinstance(attrs, dict) else None
        if isinstance(categories, dict) and categories:
            lines.append("  Categories: " + ", ".join(f"{key}: {value}" for key, value in sorted(categories.items())))
        lines.extend(self._generic_collector_section(data, ("httpx", "whatweb", "wappalyzer", "webanalyze", "technolog")))
        return lines

    def _tracking_ids(self, data):
        return self._generic_collector_section(data, ("tracking", "analytics", "identifier", "tracker"))

    def _passive_dns(self, data):
        return self._generic_collector_section(data, ("passivedns", "historicaldns", "dnsdb", "securitytrails"), limit=5000)

    def _reputation(self, data):
        attrs = self._vt_attributes(data)
        if not isinstance(attrs, dict):
            return []
        lines = []
        stats = attrs.get("last_analysis_stats")
        if isinstance(stats, dict):
            lines.append("  VirusTotal detections: " + ", ".join(f"{key}: {value}" for key, value in sorted(stats.items())))
        reputation = attrs.get("reputation")
        if reputation is not None:
            lines.append(f"  VirusTotal community reputation score: {reputation}")
        first_seen = self._format_date(attrs.get("first_seen_date"))
        if first_seen:
            lines.append(f"  First seen by VirusTotal: {first_seen}")
        analysis_date = self._format_date(attrs.get("last_analysis_date"))
        if analysis_date:
            lines.append(f"  Last analysis: {analysis_date}")
        results = attrs.get("last_analysis_results")
        flagged = []
        if isinstance(results, dict):
            for engine, details in results.items():
                if isinstance(details, dict) and details.get("category") in {"malicious", "suspicious"}:
                    flagged.append(f"{engine}: {details.get('category')}")
        if flagged:
            lines.append("  Flagged engines: " + ", ".join(sorted(flagged)[:20]))
            if len(flagged) > 20:
                lines.append(f"  ... and {len(flagged) - 20} more flagged engines")
        return lines