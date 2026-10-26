"""Offline tests for executor timing and IP timing presentation."""

from __future__ import annotations

from copy import deepcopy
from io import StringIO
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from rich.console import Console

from core.ip_responder import _print_collector_timing
from registry.collectors import ComponentSpec
from registry.executor import ComponentResult, InvestigationResult, _invoke
from ui.theme import THEME


def _collector(name: str, duration: float | None) -> dict:
    collector = {"name": name, "status": "success", "result": {"status": "success"}}
    if duration is not None:
        collector["duration_seconds"] = duration
    return collector


class ExecutorTimingTests(unittest.TestCase):
    def test_component_duration_is_nonnegative_and_does_not_mutate_payload(self) -> None:
        payload = {"status": "success", "nested": {"value": "kept"}}
        original = deepcopy(payload)
        component = ComponentSpec("Fixture", "example.collector", "run")
        module = SimpleNamespace(run=lambda target: payload)

        with patch("registry.executor.importlib.import_module", return_value=module):
            result = _invoke(component, "203.0.113.10")

        self.assertGreaterEqual(result.duration_seconds, 0)
        self.assertEqual(payload, original)
        self.assertNotIn("duration_seconds", payload)

    def test_slow_mocked_collector_duration_is_recorded(self):
        import time
        from types import SimpleNamespace
        from unittest.mock import patch

        from registry.executor import _invoke
        from registry.collectors import ComponentSpec

        module = SimpleNamespace(
            run=lambda target: (
                time.sleep(0.05) or
                {"status": "success", "target": target}
            )
        )

        component = ComponentSpec(
            name="Slow test collector",
            module="test_slow_collector",
            function="run",
        )

        with patch(
            "registry.executor.importlib.import_module",
            return_value=module,
        ):
            result = _invoke(component, "example.com")

        self.assertEqual(result.status, "success")
        self.assertGreaterEqual(result.duration_seconds, 0.04)

    def test_component_duration_survives_investigation_serialization(self) -> None:
        payload = {"status": "success", "value": "raw"}
        collector = ComponentResult("Fixture", "example.collector", "run", "success", 1.2345, payload)
        investigation = InvestigationResult(
            original_target="203.0.113.10",
            entity_type="ip_address",
            normalized_target="203.0.113.10",
            status="success",
            normalizer=None,
            collectors=[collector],
            started_at="2026-10-26T00:00:00+00:00",
            finished_at="2026-10-26T00:00:02+00:00",
            duration_seconds=2.0,
            errors=[],
        )

        serialized = investigation.to_dict()
        self.assertEqual(serialized["collectors"][0]["duration_seconds"], 1.2345)
        self.assertEqual(serialized["collectors"][0]["result"], payload)


class ResponderTimingTests(unittest.TestCase):
    def _render_timing(self, collectors: list[dict]) -> str:
        console = Console(file=StringIO(), record=True, width=160, color_system=None, theme=THEME)
        _print_collector_timing(console, {"collectors": collectors})
        return console.export_text()

    def test_slowest_collector_summary_is_descending(self) -> None:
        text = self._render_timing([
            _collector("Fast", 0.2),
            _collector("Slow", 3.0),
            _collector("Medium", 1.5),
            _collector("Fourth", 0.5),
        ])
        self.assertIn("Slowest Collector Operations", text)
        self.assertLess(text.index("Slow"), text.index("Medium"))
        self.assertLess(text.index("Medium"), text.index("Fourth"))
        self.assertNotIn("Fast", text)
        self.assertIn("Slow Operations", text)

    def test_missing_timing_fields_are_ignored(self) -> None:
        text = self._render_timing([_collector("No timing", None)])
        self.assertEqual(text, "")


if __name__ == "__main__":
    unittest.main()
