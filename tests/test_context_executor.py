"""Offline tests for IP context extraction and executor status semantics."""

from __future__ import annotations

from copy import deepcopy
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from registry.collectors import ComponentSpec
from registry.executor import ComponentResult, _invoke, _overall_status, _result_status
from tools.ip.context import run as build_context


class ContextExtractionTests(unittest.TestCase):
    def test_nested_rdap_registration_is_extracted_with_provenance(self) -> None:
        observations = {
            "rdap": {
                "status": "success",
                "registration": {
                    "name": "EXAMPLE-NET",
                    "handle": "NET-203-0-113-0-1",
                    "country": "US",
                    "start_address": "203.0.113.0",
                    "end_address": "203.0.113.255",
                    "cidr_prefixes": ["203.0.113.0/24"],
                    "parent_handle": "PARENT-NET",
                },
            },
        }
        original = deepcopy(observations)

        with patch("urllib.request.urlopen", side_effect=AssertionError("network access")):
            result = build_context("203.0.113.10", observations)

        registration = result["context"]["registration"]
        self.assertEqual(registration["network_name"], "EXAMPLE-NET")
        self.assertEqual(registration["cidr_prefixes"], ["203.0.113.0/24"])
        self.assertEqual(observations, original)
        self.assertIn(
            {"module": "rdap", "raw_status": "success"},
            result["summary"]["source_outcomes"],
        )
        self.assertEqual(result["summary"]["section_sources"]["registration"], ["rdap"])

    def test_nested_reputation_is_extracted_as_source_reported_indicators(self) -> None:
        result = build_context("203.0.113.10", {
            "reputation": {
                "status": "success",
                "assessment": {
                    "summary": "source_reports_positive_indicators",
                    "positive_indicators": ["spam"],
                    "indicator_count": 1,
                },
                "network": {"asn": 64500, "asn_name": "Example ASN", "country": "US"},
                "usage": {"hosting": True, "mobile": False},
                "reputation": {"spam": True, "proxy": False},
            },
        })

        reputation = result["context"]["reputation"]
        self.assertEqual(reputation["source_assessment"], "source_reports_positive_indicators")
        self.assertEqual(reputation["network_asn"], 64500)
        self.assertEqual(reputation["source_reported_usage_indicators"], ["hosting"])
        self.assertEqual(reputation["source_reported_reputation_indicators"], ["spam"])
        self.assertNotIn("risk", reputation)

    def test_not_found_source_is_provenance_not_negative_evidence(self) -> None:
        result = build_context("203.0.113.10", {
            "reverse_dns": {
                "status": "not_found",
                "hostnames": [],
                "error": "No PTR record",
            },
        })

        self.assertNotIn("reverse_dns", result["context"])
        self.assertIn(
            {"module": "reverse_dns", "raw_status": "not_found"},
            result["summary"]["source_outcomes"],
        )

    def test_partial_history_keeps_successful_source_summary(self) -> None:
        history = {
            "status": "partial",
            "source_count": 2,
            "successful_sources": 1,
            "summary": {"routing_observations": 4, "certificate_records": 0},
            "sources": {
                "routing_history": {"status": "success", "records": [{"prefix": "203.0.113.0/24"}]},
                "certificate_transparency": {"status": "error", "records": []},
            },
        }
        result = build_context("203.0.113.10", {"history": history})

        self.assertEqual(result["context"]["historical"]["successful_sources"], 1)
        self.assertEqual(result["context"]["historical"]["routing_observations"], 4)
        self.assertNotIn("sources", result["context"]["historical"])


class ExecutorStatusTests(unittest.TestCase):
    def test_unknown_and_not_found_are_explicit_no_result_statuses(self) -> None:
        unknown = {"status": "unknown", "detail": "source had no matching route"}
        not_found = {"status": "not_found", "records": []}
        self.assertEqual(_result_status(unknown), "no_result")
        self.assertEqual(_result_status(not_found), "no_result")
        self.assertEqual(unknown["status"], "unknown")
        self.assertEqual(not_found["status"], "not_found")

    def test_timeout_remains_distinct_from_other_collection_failures(self) -> None:
        payload = {"status": "timeout", "error": "Source did not respond"}
        self.assertEqual(_result_status(payload), "timeout")
        self.assertEqual(payload["status"], "timeout")

    def test_unrecognized_declared_status_is_partial_not_success_or_error(self) -> None:
        payload = {"status": "not_available", "reason": "source disabled"}
        self.assertEqual(_result_status(payload), "partial")
        self.assertEqual(payload["status"], "not_available")

    def test_invoke_preserves_raw_no_result_payload(self) -> None:
        payload = {"status": "not_found", "hostnames": []}
        component = ComponentSpec("Reverse DNS", "example.collector", "run")
        module = SimpleNamespace(run=lambda target: payload)

        with patch("registry.executor.importlib.import_module", return_value=module):
            result = _invoke(component, "203.0.113.10")

        self.assertEqual(result.status, "no_result")
        self.assertIs(result.result, payload)
        self.assertEqual(payload["status"], "not_found")

    def test_partial_history_component_remains_partial(self) -> None:
        history = {"status": "partial", "sources": {"routing_history": {"status": "success"}}}
        self.assertEqual(_result_status(history), "partial")
        self.assertEqual(_overall_status([
            ComponentResult("Historical intelligence", "tools.ip.history", "run", "partial", 0.0, history),
            ComponentResult("Reverse DNS", "tools.ip.reverse_dns", "run", "no_result", 0.0, {"status": "not_found"}),
        ]), "partial")


if __name__ == "__main__":
    unittest.main()
