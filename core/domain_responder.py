from datetime import datetime, timezone
import re

class DomainResponder:
    """Turn domain collector results into a readable, non-destructive report."""

    def respond(self, entity, results):
        data = {str(name): result for name, result in results}
        sections = []

        self._add_section(sections, "Identity & Registration", self._identity(entity, data))
        self._add_section(sections, "DNS & Hosting", self._dns(data))
        self._add_section(sections, "Subdomains", self._subdomains(data))
        self._add_section(sections, "Email Security", self._email_security(data))
        self._add_section(sections, "Certificates", self._certificates(data))
        self._add_section(sections, "Lookalikes", self._lookalikes(data))
        self._add_section(sections, "Takeover Risk", self._takeover(data))
        self._add_section(sections, "Web Presence & Technology", self._web_presence(data))
        self._add_section(sections, "Tracking-ID Pivots", self._tracking_ids(data))
        self._add_section(sections, "Passive DNS", self._passive_dns(data))
        self._add_section(sections, "Reputation & Threat Intelligence", self._reputation(data))

        return "\n\n".join(sections)

    @staticmethod
    def _add_section(sections, title, lines):
        if lines:
            sections.append(title + "\n" + "\n".join(lines))

    @staticmethod
    def _tool(data, *terms):
        """Return the first result whose collector name contains a given term."""
        for name, result in data.items():
            normalized = re.sub(r"[^a-z0-9]", "", name.lower())
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

    @staticmethod
    def _list(value):
        if value is None:
            return []
        if isinstance(value, (list, tuple, set)):
            return [str(item).strip() for item in value if item is not None and str(item).strip()]
        if isinstance(value, str):
            return [line.strip() for line in value.splitlines() if line.strip()]
        return [str(value).strip()] if str(value).strip() else []

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
                return match.group(1).strip()
        return None

    @staticmethod
    def _vt_attributes(data):
        vt = DomainResponder._tool(data, "virustotal", "vttool")
        return DomainResponder._get(vt, "data", "attributes") if isinstance(vt, dict) else None

    def _identity(self, entity, data):
        lines = []
        target = getattr(entity, "value", None) or getattr(entity, "target", None)
        if target:
            lines.append(f"  Domain: {target}")

        whois = self._tool(data, "whois")
        if not isinstance(whois, str):
            whois = ""
        rdap = self._tool(data, "rdap")
        vt_attrs = self._vt_attributes(data)
        vt_whois = self._get(vt_attrs, "whois")
        if not isinstance(vt_whois, str):
            vt_whois = ""

        fields = [
            ("Registrar", [r"^Registrar:\s*(.+)$", r"^Registrar Name:\s*(.+)$"]),
            ("Created", [r"^(?:Creation Date|Created On|Create date):\s*(.+)$"]),
            ("Updated", [r"^(?:Updated Date|Last Updated On|Update date):\s*(.+)$"]),
            ("Expires", [r"^(?:Registry Expiry Date|Registrar Registration Expiration Date|Expiry date):\s*(.+)$"]),
            ("Registrant organization", [r"^Registrant Organization:\s*(.+)$", r"^Registrant company:\s*(.+)$"]),
            ("Registrant country", [r"^Registrant Country:\s*(.+)$", r"^Registrant country:\s*(.+)$"]),
        ]
        for label, patterns in fields:
            value = self._first_regex(whois, patterns) or self._first_regex(vt_whois, patterns)
            if value:
                lines.append(f"  {label}: {value}")

        if isinstance(rdap, dict):
            domain_name = self._get(rdap, "ldhName") or self._get(rdap, "ldh_name")
            if domain_name and not target:
                lines.insert(0, f"  Domain: {domain_name}")
            status = self._list(rdap.get("status"))
            if status:
                lines.append("  Status: " + ", ".join(status))
            secure_dns = rdap.get("secureDNS") or rdap.get("secure_dns")
            if isinstance(secure_dns, dict):
                signed = secure_dns.get("delegationSigned", secure_dns.get("delegation_signed"))
                if signed is not None:
                    lines.append(f"  DNSSEC: {'signed' if signed else 'unsigned'}")

        dnssec = self._first_regex(whois, [r"^DNSSEC:\s*(.+)$"]) or self._first_regex(vt_whois, [r"^DNSSEC:\s*(.+)$"])
        if dnssec and not any(line.startswith("  DNSSEC:") for line in lines):
            lines.append(f"  DNSSEC: {dnssec}")

        check = self._tool(data, "checkdmarc")
        if isinstance(check, dict) and not any(line.startswith("  DNSSEC:") for line in lines):
            if check.get("dnssec") is not None:
                lines.append(f"  DNSSEC: {'signed' if check['dnssec'] else 'unsigned'}")

        return lines

    def _dns(self, data):
        lines = []
        dig = self._tool(data, "dig")
        dnsx = self._tool(data, "dnsx")
        vt_attrs = self._vt_attributes(data)
        vt_records = self._get(vt_attrs, "last_dns_records")
        check = self._tool(data, "checkdmarc")
        seen = set()

        def add(record_type, value):
            value = str(value).strip().strip('"')
            if not value:
                return
            key = (record_type.upper(), value.lower())
            if key in seen:
                return
            seen.add(key)
            lines.append(f"  {record_type.upper()}: {value}")

        if isinstance(dig, dict):
            for record_type in ("A", "AAAA", "CNAME", "NS", "MX", "SOA", "CAA", "SRV", "TXT"):
                raw = dig.get(record_type)
                if not raw:
                    continue
                for record in str(raw).splitlines():
                    fields = record.split()
                    if "IN" in fields:
                        index = fields.index("IN")
                        if len(fields) > index + 2:
                            add(record_type, " ".join(fields[index + 2:]))
                    else:
                        add(record_type, record)
        elif isinstance(dnsx, str):
            for line in dnsx.splitlines():
                match = re.match(r"\S+\s+\[([^]]+)\]\s+\[(.*)]", line.strip())
                if match:
                    add(match.group(1), match.group(2))

        if isinstance(vt_records, list):
            for record in vt_records:
                if not isinstance(record, dict):
                    continue
                record_type = record.get("type")
                value = record.get("value")
                if record_type == "SOA" and value:
                    value = " ".join(str(record.get(k)) for k in ("value", "rname", "serial", "refresh", "retry", "expire", "minimum") if record.get(k) is not None)
                elif record_type == "CAA" and record.get("tag"):
                    value = f"{record.get('flag', 0)} {record['tag']} {value}"
                if record_type and value:
                    add(record_type, value)

        if isinstance(check, dict):
            for key, record_type in (("ns", "NS"), ("mx", "MX")):
                block = check.get(key)
                if isinstance(block, dict):
                    values = block.get("hostnames") if key == "ns" else block.get("hosts")
                    for value in self._list(values):
                        add(record_type, value)

        return lines

    def _subdomains(self, data):
        combined = {}
        for tool_terms, source in ((("subfinder",), "subfinder"), (("assetfinder",), "assetfinder")):
            result = self._tool(data, *tool_terms)
            for hostname in self._list(result):
                hostname = hostname.strip().lower().rstrip(".")
                if hostname and not hostname.startswith(("[", "error:")):
                    combined.setdefault(hostname, set()).add(source)
        lines = []
        for hostname in sorted(combined):
            sources = ", ".join(sorted(combined[hostname]))
            lines.append(f"  {hostname} [{sources}]")
        if lines:
            lines.insert(0, f"  Total unique subdomains: {len(combined)}")
        return lines

    def _email_security(self, data):
        lines = []
        check = self._tool(data, "checkdmarc")
        if not isinstance(check, dict):
            return lines
        for key, label in (("mx", "MX"), ("spf", "SPF"), ("dmarc", "DMARC"), ("mta_sts", "MTA-STS"), ("smtp_tls_reporting", "SMTP TLS Reporting"), ("bimi", "BIMI")):
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
                    lines.append(f"  {label}: " + ", ".join(formatted))
                elif "hosts" in block:
                    lines.append("  MX: no MX hosts returned")
            elif record:
                lines.append(f"  {label}: {record}" + (f" (valid: {valid})" if valid is not None else ""))
            elif valid is not None:
                lines.append(f"  {label}: {'valid' if valid else 'not detected or invalid'}")
            error = block.get("error")
            if error:
                lines.append(f"    Note: {error}")
            for warning in self._list(block.get("warnings")):
                lines.append(f"    Warning: {warning}")

        for warning in self._list(check.get("warnings")):
            lines.append(f"  Warning: {warning}")
        return lines

    def _certificates(self, data):
        lines = []
        attrs = self._vt_attributes(data)
        cert = self._get(attrs, "last_https_certificate")
        if not isinstance(cert, dict):
            return lines
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
        if sans:
            unique = sorted(set(str(name) for name in sans))
            lines.append(f"  Subject alternative names ({len(unique)}): " + ", ".join(unique[:30]))
            if len(unique) > 30:
                lines.append(f"  ... and {len(unique) - 30} more SAN entries")
        thumbprint = cert.get("thumbprint_sha256")
        if thumbprint:
            lines.append(f"  SHA-256 fingerprint: {thumbprint}")
        return lines

    def _lookalikes(self, data):
        result = self._tool(data, "dnstwist")
        if not isinstance(result, list):
            return []
        lines = []
        variants = []
        for item in result:
            if not isinstance(item, dict):
                continue
            domain = item.get("domain")
            fuzzer = item.get("fuzzer")
            if not domain or fuzzer == "*original":
                continue
            addresses = self._list(item.get("dns_a")) + self._list(item.get("dns_aaaa"))
            nameservers = self._list(item.get("dns_ns"))
            detail = []
            if addresses:
                detail.append("IPs: " + ", ".join(addresses))
            if nameservers:
                detail.append("NS: " + ", ".join(nameservers))
            variants.append((str(fuzzer or "other"), str(domain), "; ".join(detail)))
        if variants:
            lines.append(f"  Candidate domains: {len(variants)}")
            for fuzzer, domain, detail in sorted(variants, key=lambda item: (item[0], item[1]))[:100]:
                line = f"  {domain} ({fuzzer})"
                if detail:
                    line += f" | {detail}"
                lines.append(line)
            if len(variants) > 100:
                lines.append(f"  ... and {len(variants) - 100} more candidates")
        return lines

    def _takeover(self, data):
        result = self._tool(data, "takeover", "subjack", "nuclei")
        if result is None:
            return []
        lines = []
        if isinstance(result, str):
            lines.extend(f"  {line}" for line in result.splitlines() if line.strip())
        elif isinstance(result, (dict, list)):
            rendered = repr(result)
            lines.append("  Collector output: " + rendered[:3000])
        return lines

    def _web_presence(self, data):
        lines = []
        attrs = self._vt_attributes(data)
        if isinstance(attrs, dict):
            categories = attrs.get("categories")
            if isinstance(categories, dict) and categories:
                lines.append("  Categories: " + ", ".join(f"{key}: {value}" for key, value in categories.items()))
        for name, result in data.items():
            normalized = re.sub(r"[^a-z0-9]", "", name.lower())
            if any(term in normalized for term in ("httpx", "whatweb", "wappalyzer", "webanalyze", "technolog")):
                if isinstance(result, str):
                    lines.extend(f"  {line}" for line in result.splitlines() if line.strip())
                elif isinstance(result, (dict, list)) and result:
                    lines.append(f"  {name}: {str(result)[:3000]}")
        return lines

    def _tracking_ids(self, data):
        lines = []
        attrs = self._vt_attributes(data)
        for name, result in data.items():
            normalized = re.sub(r"[^a-z0-9]", "", name.lower())
            if any(term in normalized for term in ("tracking", "analytics", "identifier", "tracker")):
                if isinstance(result, str):
                    lines.extend(f"  {line}" for line in result.splitlines() if line.strip())
                elif isinstance(result, (dict, list)) and result:
                    lines.append(f"  {name}: {str(result)[:3000]}")
        return lines

    def _passive_dns(self, data):
        lines = []
        for name, result in data.items():
            normalized = re.sub(r"[^a-z0-9]", "", name.lower())
            if any(term in normalized for term in ("passivedns", "historicaldns", "dnsdb", "securitytrails")):
                if isinstance(result, str):
                    lines.extend(f"  {line}" for line in result.splitlines() if line.strip())
                elif isinstance(result, (dict, list)) and result:
                    lines.append(f"  {name}: {str(result)[:5000]}")
        return lines

    def _reputation(self, data):
        lines = []
        attrs = self._vt_attributes(data)
        if not isinstance(attrs, dict):
            return lines
        stats = attrs.get("last_analysis_stats")
        if isinstance(stats, dict):
            lines.append("  VirusTotal detections: " + ", ".join(f"{key}: {value}" for key, value in stats.items()))
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