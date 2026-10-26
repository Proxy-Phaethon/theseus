"""Offline regression tests for the IP responder's collector schemas."""

from __future__ import annotations

from copy import deepcopy
from io import StringIO
import unittest
from unittest.mock import patch

from rich.console import Console

from core.ip_responder import IPResponder
from ui.theme import THEME


def _investigation(results: dict[str, dict]) -> dict:
    return {
        "entity_type": "ip_address",
        "original_target": "203.0.113.10",
        "normalized_target": "203.0.113.10",
        "status": "partial",
        "normalizer": {"result": {"status": "success", "version": 4}},
        "collectors": [
            {"name": name, "status": "success", "result": result}
            for name, result in results.items()
        ],
        "duration_seconds": 0.1,
        "completed_count": len(results),
        "failed_count": 0,
        "errors": [],
    }


def _render(results: dict[str, dict]) -> str:
    console = Console(file=StringIO(), record=True, width=180, color_system=None, theme=THEME)
    # The responder must only render supplied payloads; collectors are never run.
    with patch("socket.create_connection", side_effect=AssertionError("network access")), patch(
        "urllib.request.urlopen", side_effect=AssertionError("network access")
    ):
        IPResponder.respond(_investigation(results), console)
    return console.export_text()


class IPResponderSchemaTests(unittest.TestCase):
    def test_nested_rdap_registration_renders(self) -> None:
        text = _render({"RDAP lookup": {
            "status": "success",
            "registration": {
                "name": "EXAMPLE-NET", "country": "US",
                "start_address": "203.0.113.0", "end_address": "203.0.113.255",
                "cidr_prefixes": ["203.0.113.0/24"], "parent_handle": "PARENT",
                "status": ["active"], "events": [{"action": "registration", "date": "2020-01-01"}],
                "contacts": [{"roles": ["technical"], "name": "Example Admin", "organization": "Example Org"}],
            },
        }})
        self.assertIn("EXAMPLE-NET", text)
        self.assertIn("203.0.113.0/24", text)
        self.assertIn("Example Admin", text)

    def test_tls_nested_certificate_and_probe_failure_render(self) -> None:
        text = _render({"TLS intelligence": {
            "status": "success",
            "certificates": [{
                "port": 443,
                "certificate": {
                    "subject_common_names": ["www.example.test"],
                    "issuer": [{"value": "Example Issuer"}],
                    "validity": {"not_after": "2030-01-01T00:00:00+00:00", "days_until_expiry": 100},
                    "fingerprints": {"sha256": "abcdef0123456789"},
                },
                "certificate_verification": {"status": "passed"},
            }],
            "results": [{"port": 443, "status": "success"}, {"port": 8443, "service_guess": "HTTPS", "status": "timeout", "error": {"message": "timed out"}}],
        }})
        self.assertIn("www.example.test", text)
        self.assertIn("Example Issuer", text)
        self.assertIn("2030-01-01", text)
        self.assertIn("Passed", text)
        self.assertIn("TLS Probe Outcomes", text)

    def test_http_uses_actual_http_status_and_separate_failures(self) -> None:
        text = _render({"HTTP intelligence": {
            "status": "success",
            "responding_endpoints": [{"port": 80, "scheme": "http", "http_status": 302, "headers": {"server": "nginx"}, "redirect": {"location": "https://example.test/"}}],
            "results": [
                {"port": 80, "status": "success", "security_headers": {"present": {"strict-transport-security": {"name": "HSTS"}}}, "technology_indicators": [{"value": "nginx/1.25"}]},
                {"port": 443, "scheme": "https", "status": "timeout", "error": {"message": "timed out"}},
            ],
        }})
        self.assertIn("302", text)
        self.assertNotIn("HTTP status  success", text)
        self.assertIn("HTTP Probe Outcomes", text)
        self.assertIn("nginx/1.25", text)
        self.assertNotIn("dict_keys", text)

    def test_reputation_nested_fields_do_not_render_python_dicts(self) -> None:
        text = _render({"IP reputation": {
            "status": "success",
            "assessment": {"summary": "source_reports_positive_indicators", "positive_indicators": ["spam"], "indicator_count": 1},
            "network": {"asn": 64500, "asn_name": "Example ASN", "country": "US"},
            "usage": {"hosting": True}, "reputation": {"spam": True},
            "source_recommendations": {"review": True},
        }})
        self.assertIn("source_reports_positive_indicators", text)
        self.assertIn("Example ASN", text)
        self.assertNotIn("{'summary'", text)

    def test_passive_dns_caps_display_but_reports_full_count(self) -> None:
        records = [{"query": f"host{index}.example", "record_type": "A", "answer": "203.0.113.10", "first_seen": "2020-01-01", "last_seen": "2021-01-01"} for index in range(11)]
        text = _render({"Passive DNS": {"status": "success", "result_count": 11, "source_count": 30, "truncated": True, "records": records}})
        self.assertIn("Returned records", text)
        self.assertIn("11", text)
        self.assertIn("Yes", text)
        self.assertIn("host9.example", text)
        self.assertNotIn("host10.example", text)

    def test_reverse_dns_filters_reverse_query_names(self) -> None:
        text = _render({"Reverse DNS": {"status": "success", "hostnames": ["10.113.0.203.in-addr.arpa", "ptr.example.test", "x.ip6.arpa"]}})
        self.assertIn("ptr.example.test", text)
        self.assertNotIn("10.113.0.203.in-addr.arpa", text)
        self.assertNotIn("x.ip6.arpa", text)

    def test_history_keeps_successful_routing_visible_when_ct_fails(self) -> None:
        text = _render({"Historical intelligence": {"status": "partial", "sources": {
            "routing_history": {"status": "success", "record_count": 1, "records": [{"origin": "AS64500", "prefix": "203.0.113.0/24", "start_time": "2020", "end_time": "2021"}]},
            "certificate_transparency": {"status": "error", "record_count": 0, "error": "service unavailable", "records": []},
        }}})
        self.assertIn("Historical Routing Observations", text)
        self.assertIn("AS64500", text)
        self.assertIn("service unavailable", text)

    def test_services_retain_evidence_and_show_failed_probe(self) -> None:
        text = _render({"Service detection": {"status": "success", "identified_services": [
            {"port": 22, "protocol": "SSH", "service_guess": "SSH", "evidence": "SSH-2.0-OpenSSH_9.0"},
        ], "results": [
            {"port": 22, "status": "identified"},
            {"port": 23, "service_guess": "Telnet", "status": "connection_refused"},
        ]}})
        self.assertIn("SSH-2.0-OpenSSH_9.0", text)
        self.assertIn("Connection refused", text)
        self.assertNotIn("vulnerability", text.lower())

    def test_vulnerability_output_is_not_labelled_confirmed(self) -> None:
        text = _render({"Vulnerability intelligence": {"status": "success", "software_candidates": [
            {"product": "nginx", "version": "1.20", "evidence_source": "http", "evidence_value": "nginx/1.20"},
        ], "kev_matches": [{"cve_id": "CVE-2024-0001", "product": "nginx", "name": "Example", "date_added": "2024-01-01"}],
        "sources": {"nvd": [{"query": "nginx 1.20", "status": "success", "vulnerabilities": [{}]}]},
        "evidence": [{"source": "http", "field": "headers.server", "value": "nginx/1.20"}],
        "limitations": ["Keyword matches require review."],
        }})
        self.assertIn("Potential KEV Product-Level Correlations", text)
        self.assertIn("not confirmed vulnerabilities", text)
        self.assertIn("Keyword matches require review.", text)
        self.assertNotIn("Confirmed Vulnerabilities", text)

    def test_responder_does_not_mutate_collector_payloads(self) -> None:
        results = {"Passive DNS": {"status": "success", "result_count": 1, "records": [{"query": "a.example", "record_type": "A", "answer": "203.0.113.10"}]}}
        original = deepcopy(results)
        _render(results)
        self.assertEqual(results, original)


if __name__ == "__main__":
    unittest.main()
