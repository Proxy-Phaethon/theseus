from __future__ import annotations

from typing import Any

from core.identifier import Entity

class URLResponder:
    def respond(
        self,
        entity: Entity,
        results: list[tuple[str, Any]],
    ) -> str:
        data = {
            tool_name: result
            for tool_name, result in results
            if isinstance(tool_name, str)
        }

        sections = []

        section_builders = (
            ("HTTP", lambda: self._http(data.get("HTTPTool", {}))),
            (
                "Redirects",
                lambda: self._redirects(data.get("HTTPTool", {})),
            ),
            ("DNS", lambda: self._dns(data.get("DNSTool", {}))),
            (
                "Page Inspection",
                lambda: self._playwright(data.get("PlaywrightTool", {})),
            ),
            (
                "Infrastructure",
                lambda: self._urlscan(data.get("URLScanTool", {})),
            ),
            (
                "Certificate Transparency",
                lambda: self._certificates(
                    data.get("CertTransparencyTool", {})
                ),
            ),
            (
                "VirusTotal",
                lambda: self._virustotal(data.get("VirusTotalTool", {})),
            ),
            (
                "Google Safe Browsing",
                lambda: self._safe_browsing(
                    data.get("SafeBrowsingTool", {})
                ),
            ),
            (
                "URLhaus",
                lambda: self._urlhaus(data.get("URLhausTool", {})),
            ),
            (
                "Wayback Machine",
                lambda: self._wayback(data.get("WaybackTool", {})),
            ),
            (
                "Common Crawl",
                lambda: self._common_crawl(
                    data.get("CommonCrawlTool", {})
                ),
            ),
        )

        for title, builder in section_builders:
            lines = builder()
            if lines:
                sections.append((title, lines))

        return self._format_sections(sections)

    @staticmethod
    def _as_dict(value: Any) -> dict:
        return value if isinstance(value, dict) else {}

    @staticmethod
    def _as_list(value: Any) -> list:
        return value if isinstance(value, list) else []

    @staticmethod
    def _add(lines: list[str], label: str, value: Any) -> None:
        if value is not None and value != "":
            lines.append(f"{label}: {value}")

    @staticmethod
    def _items(
        lines: list[str],
        label: str,
        values: Any,
        limit: int = 10,
    ) -> None:
        if not isinstance(values, list) or not values:
            return

        lines.append(f"{label} ({len(values)}):")

        for value in values[:limit]:
            lines.append(f"  {value}")

        if len(values) > limit:
            lines.append(f"  ... and {len(values) - limit} more")

    def _http(self, result: Any) -> list[str]:
        http = self._as_dict(result)
        lines = []

        for key, label in (
            ("requested_url", "Requested URL"),
            ("final_url", "Final URL"),
        ):
            self._add(lines, label, http.get(key))

        status_code = http.get("status_code")
        reason = http.get("reason")

        if status_code is not None:
            status = f"{status_code} {reason}" if reason else status_code
            self._add(lines, "Status", status)

        for key, label in (
            ("content_type", "Content Type"),
            ("content_length", "Response Size (bytes)"),
            ("response_time_ms", "Response Time (ms)"),
        ):
            self._add(lines, label, http.get(key))

        headers = self._as_dict(http.get("headers"))

        for key in ("server", "location", "last-modified", "etag"):
            value = next(
                (
                    header_value
                    for header_name, header_value in headers.items()
                    if header_name.lower() == key
                ),
                None,
            )
            self._add(lines, f"Header {key}", value)

        return lines

    def _redirects(self, result: Any) -> list[str]:
        http = self._as_dict(result)
        redirects = self._as_list(http.get("redirects"))

        if not redirects:
            return []

        lines = []

        for redirect in redirects:
            redirect = self._as_dict(redirect)
            source = redirect.get("url")
            destination = redirect.get("location")
            status = redirect.get("status_code")

            if not source:
                continue

            detail = f"{source}"

            if destination:
                detail += f" -> {destination}"

            if status is not None:
                detail += f" ({status})"

            lines.append(detail)

        return lines

    def _dns(self, result: Any) -> list[str]:
        dns = self._as_dict(result)
        records = self._as_dict(dns.get("records"))

        if not records:
            return []

        lines = []
        self._add(lines, "Hostname", dns.get("hostname"))

        for record_type in ("A", "AAAA", "CNAME", "MX", "NS", "TXT"):
            values = self._as_list(records.get(record_type))

            if values:
                lines.append(f"{record_type}:")
                for value in values:
                    lines.append(f"  {value}")

        return lines

    def _playwright(self, result: Any) -> list[str]:
        page = self._as_dict(result)

        if not page:
            return []

        lines = []

        for key, label in (
            ("final_url", "Final URL"),
            ("title", "Title"),
            ("status_code", "Browser Status"),
            ("content_type", "Content Type"),
            ("dom_length", "DOM Length"),
            ("dom_sha256", "DOM SHA-256"),
            ("elapsed_ms", "Elapsed (ms)"),
        ):
            self._add(lines, label, page.get(key))

        redirects = self._as_list(page.get("redirects"))
        if redirects:
            lines.append("Browser Redirects:")
            for redirect in redirects[:10]:
                redirect = self._as_dict(redirect)
                source = redirect.get("url")
                destination = redirect.get("location")
                status = redirect.get("status_code")

                if source:
                    detail = f"  {source}"
                    if destination:
                        detail += f" -> {destination}"
                    if status is not None:
                        detail += f" ({status})"
                    lines.append(detail)

        links = self._as_list(page.get("links"))
        if links:
            lines.append(f"Links ({len(links)} returned):")
            for link in links[:10]:
                link = self._as_dict(link)
                text = link.get("text") or "(no text)"
                href = link.get("href")
                if href:
                    lines.append(f"  {text}: {href}")
            if len(links) > 10:
                lines.append(f"  ... and {len(links) - 10} more")

        forms = self._as_list(page.get("forms"))
        if forms:
            lines.append(f"Forms ({len(forms)}):")
            for form in forms[:10]:
                form = self._as_dict(form)
                action = form.get("action", "")
                method = form.get("method", "GET")
                fields = self._as_list(form.get("fields"))
                field_names = [
                    self._as_dict(field).get("name")
                    for field in fields
                ]
                field_names = [name for name in field_names if name]

                detail = f"  {method} {action}"
                if field_names:
                    detail += f" | Fields: {', '.join(field_names)}"
                lines.append(detail)

        requests_seen = self._as_list(page.get("requests"))
        if requests_seen:
            resource_types = {}
            for request in requests_seen:
                request = self._as_dict(request)
                resource_type = request.get("resource_type", "unknown")
                resource_types[resource_type] = (
                    resource_types.get(resource_type, 0) + 1
                )

            summary = ", ".join(
                f"{kind}: {count}"
                for kind, count in sorted(resource_types.items())
            )
            lines.append(f"Browser Requests: {len(requests_seen)}")
            if summary:
                lines.append(f"  Resource Types: {summary}")

        failed = self._as_list(page.get("failed_requests"))
        if failed:
            lines.append(f"Failed Requests ({len(failed)}):")
            for item in failed[:10]:
                item = self._as_dict(item)
                lines.append(
                    f"  {item.get('url', 'Unknown URL')}: "
                    f"{item.get('error') or 'Request failed'}"
                )

        for key, label in (
            ("console_errors", "Console Errors"),
            ("page_errors", "Page Errors"),
        ):
            errors = self._as_list(page.get(key))
            if errors:
                lines.append(f"{label} ({len(errors)}):")
                for error in errors[:5]:
                    lines.append(f"  {error}")
                if len(errors) > 5:
                    lines.append(f"  ... and {len(errors) - 5} more")

        return lines

    def _urlscan(self, result: Any) -> list[str]:
        wrapper = self._as_dict(result)

        if not wrapper:
            return []

        lines = []
        self._add(lines, "Scan Status", wrapper.get("status"))
        self._add(lines, "Visibility", wrapper.get("visibility"))
        self._add(lines, "Scan ID", wrapper.get("scan_id"))
        self._add(lines, "Result URL", wrapper.get("result_url"))

        raw = self._as_dict(wrapper.get("raw_result"))
        if not raw:
            message = wrapper.get("message")
            self._add(lines, "Message", message)
            return lines

        page = self._as_dict(
            self._as_dict(raw.get("page"))
        )
        for key, label in (
            ("title", "Page Title"),
            ("url", "Scanned URL"),
            ("domain", "Domain"),
            ("ip", "IP Address"),
            ("asn", "ASN"),
            ("asnname", "ASN Name"),
            ("server", "Server"),
            ("status", "HTTP Status"),
            ("tlsIssuer", "TLS Issuer"),
            ("tlsValidFrom", "TLS Valid From"),
            ("tlsValidDays", "TLS Valid Days"),
            ("domainAgeDays", "Domain Age (days)"),
            ("umbrellaRank", "Umbrella Rank"),
        ):
            self._add(lines, label, page.get(key))

        verdicts = self._as_dict(raw.get("verdicts"))
        for verdict_type in ("overall", "community", "engines"):
            verdict = self._as_dict(verdicts.get(verdict_type))
            if not verdict:
                continue

            malicious = verdict.get("malicious")
            score = verdict.get("score")
            details = []

            if malicious is not None:
                details.append(f"malicious={malicious}")
            if score is not None:
                details.append(f"score={score}")

            if details:
                lines.append(
                    f"{verdict_type.title()} Verdict: {', '.join(details)}"
                )

        lists = self._as_dict(raw.get("lists"))
        for key, label in (
            ("domains", "Observed Domains"),
            ("ips", "Observed IPs"),
            ("linkDomains", "Linked Domains"),
            ("servers", "Observed Servers"),
            ("urls", "Observed URLs"),
        ):
            values = lists.get(key)
            self._items(lines, label, values, limit=10)

        stats = self._as_dict(raw.get("stats"))
        for key, label in (
            ("totalLinks", "Total Links"),
            ("malicious", "Malicious Items"),
            ("securePercentage", "Secure Requests (%)"),
            ("secureRequests", "Secure Requests"),
        ):
            self._add(lines, label, stats.get(key))

        return lines

    def _certificates(self, result: Any) -> list[str]:
        data = self._as_dict(result)

        if not data:
            return []

        lines = []
        self._add(lines, "Queried Domain", data.get("queried_domain"))
        self._add(lines, "Certificate Records", data.get("certificate_count"))
        self._add(lines, "Concrete Hostnames", data.get("hostname_count"))
        self._add(lines, "Wildcard Patterns", data.get("wildcard_count"))
        self._add(lines, "Elapsed (ms)", data.get("elapsed_ms"))

        self._items(
            lines,
            "Hostnames",
            data.get("hostnames"),
            limit=20,
        )
        self._items(
            lines,
            "Wildcard Patterns",
            data.get("wildcard_names"),
            limit=20,
        )

        certificates = self._as_list(data.get("certificates"))
        if certificates:
            lines.append(f"Certificate Samples ({min(10, len(certificates))}):")

            for certificate in certificates[:10]:
                certificate = self._as_dict(certificate)
                cert_id = certificate.get("id", "unknown")
                names = certificate.get("name_value", "")
                not_before = certificate.get("not_before")
                not_after = certificate.get("not_after")
                issuer = certificate.get("issuer_name")

                lines.append(f"  ID: {cert_id}")

                if names:
                    names_list = names.splitlines()
                    for name in names_list[:5]:
                        lines.append(f"    Name: {name}")
                    if len(names_list) > 5:
                        lines.append(
                            f"    ... and {len(names_list) - 5} more names"
                        )

                self._add(lines, "    Not Before", not_before)
                self._add(lines, "    Not After", not_after)
                self._add(lines, "    Issuer", issuer)

        return lines

    def _virustotal(self, result: Any) -> list[str]:
        wrapper = self._as_dict(result)

        if not wrapper:
            return []

        lines = []
        status = wrapper.get("status")
        self._add(lines, "Report Status", status)

        raw = self._as_dict(wrapper.get("raw_result"))
        attributes = self._as_dict(
            self._as_dict(raw.get("data")).get("attributes")
        )

        if not attributes:
            return lines

        self._add(lines, "Reputation Score", attributes.get("reputation"))
        self._add(lines, "Last Final URL", attributes.get("last_final_url"))
        self._add(
            lines,
            "Last HTTP Status",
            attributes.get("last_http_response_code"),
        )
        self._add(lines, "Title", attributes.get("title"))
        self._add(lines, "Times Submitted", attributes.get("times_submitted"))

        stats = self._as_dict(attributes.get("last_analysis_stats"))
        if stats:
            lines.append("Last Analysis:")
            for key in (
                "malicious",
                "suspicious",
                "harmless",
                "undetected",
                "timeout",
            ):
                self._add(lines, f"  {key.title()}", stats.get(key))

        votes = self._as_dict(attributes.get("total_votes"))
        if votes:
            lines.append("Community Votes:")
            self._add(lines, "  Harmless", votes.get("harmless"))
            self._add(lines, "  Malicious", votes.get("malicious"))

        categories = self._as_dict(attributes.get("categories"))
        if categories:
            lines.append("Categories:")
            for source, category in list(categories.items())[:10]:
                lines.append(f"  {source}: {category}")

        links = self._as_list(attributes.get("outgoing_links"))
        self._items(lines, "Outgoing Links", links, limit=10)

        return lines

    def _safe_browsing(self, result: Any) -> list[str]:
        data = self._as_dict(result)

        if not data:
            return []

        lines = []
        status = data.get("status")

        descriptions = {
            "match_found": "Threat match found",
            "no_match": "No threat match returned (not a safety guarantee)",
        }

        self._add(
            lines,
            "Result",
            descriptions.get(status, status),
        )

        raw = self._as_dict(data.get("raw_result"))
        matches = self._as_list(raw.get("matches"))

        for match in matches[:10]:
            match = self._as_dict(match)
            threat_type = match.get("threatType", "Unknown threat")
            platform = match.get("platformType", "Unknown platform")
            entry = self._as_dict(match.get("threat", {}))
            threat_url = entry.get("url")

            detail = f"{threat_type} | {platform}"
            if threat_url:
                detail += f" | {threat_url}"

            lines.append(detail)

        if len(matches) > 10:
            lines.append(f"... and {len(matches) - 10} more matches")

        return lines

    def _urlhaus(self, result: Any) -> list[str]:
        data = self._as_dict(result)

        if not data:
            return []

        lines = []
        status = data.get("status")

        descriptions = {
            "found": "Matching URL record found",
            "not_found": "No matching URL record found",
            "unknown": "Query status unknown",
        }

        self._add(lines, "Result", descriptions.get(status, status))

        raw = self._as_dict(data.get("raw_result"))

        for key, label in (
            ("url", "Reported URL"),
            ("url_status", "URL Status"),
            ("host", "Host"),
            ("date_added", "Date Added"),
            ("threat", "Threat"),
            ("blacklists", "Blacklist Results"),
            ("reporter", "Reporter"),
        ):
            value = raw.get(key)
            if isinstance(value, dict):
                for subkey, subvalue in value.items():
                    self._add(lines, f"{label} {subkey}", subvalue)
            else:
                self._add(lines, label, value)

        tags = raw.get("tags")
        if isinstance(tags, list):
            self._items(lines, "Tags", tags, limit=10)

        return lines

    def _wayback(self, result: Any) -> list[str]:
        data = self._as_dict(result)

        if not data:
            return []

        lines = []
        self._add(lines, "Archive Status", data.get("status"))
        self._add(lines, "Capture Count", data.get("capture_count"))

        captures = self._as_list(data.get("captures"))
        if captures:
            lines.append(f"Capture Samples ({min(10, len(captures))}):")

            for capture in captures[:10]:
                capture = self._as_dict(capture)

                timestamp = capture.get("timestamp", "Unknown time")
                original = capture.get("original", "Unknown URL")
                status = capture.get("statuscode")
                archive_url = capture.get("archive_url")

                detail = f"  {timestamp} | {original}"
                if status:
                    detail += f" | HTTP {status}"
                lines.append(detail)

                if archive_url:
                    lines.append(f"    Archive: {archive_url}")

        return lines

    def _common_crawl(self, result: Any) -> list[str]:
        data = self._as_dict(result)

        if not data:
            return []

        lines = []
        self._add(lines, "Index", data.get("index_id"))
        self._add(lines, "Index Name", data.get("index_name"))
        self._add(lines, "Capture Count Returned", data.get("capture_count"))
        self._add(lines, "Elapsed (ms)", data.get("elapsed_ms"))

        captures = self._as_list(data.get("captures"))
        if captures:
            lines.append(f"Capture Samples ({min(10, len(captures))}):")

            for capture in captures[:10]:
                capture = self._as_dict(capture)

                timestamp = capture.get("timestamp", "Unknown time")
                url = capture.get("url", "Unknown URL")
                status = capture.get("status", "Unknown status")
                digest = capture.get("digest")

                detail = f"  {timestamp} | HTTP {status} | {url}"
                if digest:
                    detail += f" | Digest: {digest}"

                lines.append(detail)

        return lines

    @staticmethod
    def _format_sections(sections: list[tuple[str, list[str]]]) -> str:
        output = []

        for title, lines in sections:
            if not lines:
                continue

            output.append(title)

            for line in lines:
                output.append(f"  {line}")

            output.append("")

        return "\n".join(output).rstrip()