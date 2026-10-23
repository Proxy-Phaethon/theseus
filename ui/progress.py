from __future__ import annotations

from dataclasses import dataclass, field
from time import monotonic

from rich.console import Console
from rich.live import Live
from rich.spinner import Spinner
from rich.text import Text

from ui.status import format_status

@dataclass
class CollectorProgress:
    """Current display state for one collector."""

    name: str
    status: str = "pending"
    message: str = ""

@dataclass
class InvestigationProgress:
    """Track collector lifecycle and elapsed investigation time."""

    console: Console
    animate: bool = True
    collectors: dict[str, CollectorProgress] = field(default_factory=dict)
    started_at: float = field(default_factory=monotonic)
    finished_at: float | None = None

    def register(self, name: str) -> None:
        """Register a collector before it starts."""
        self.collectors[name] = CollectorProgress(name=name)
        self._refresh()

    def update(
        self,
        name: str,
        status: str,
        message: str = "",
    ) -> None:
        """Update a collector's status from a real lifecycle event."""
        if name not in self.collectors:
            self.register(name)

        self.collectors[name].status = status.strip().lower()
        self.collectors[name].message = message
        self._refresh()

    def start(self, name: str, message: str = "") -> None:
        self.update(name, "running", message)

    def complete(self, name: str, message: str = "") -> None:
        self.update(name, "success", message)

    def fail(self, name: str, message: str = "") -> None:
        self.update(name, "error", message)

    def skip(self, name: str, message: str = "") -> None:
        self.update(name, "skipped", message)

    def finish(self) -> float:
        """Mark the investigation as finished and return elapsed seconds."""
        if self.finished_at is None:
            self.finished_at = monotonic()

        self._refresh()
        return self.elapsed

    @property
    def elapsed(self) -> float:
        """Elapsed time, frozen after finish()."""
        end = self.finished_at or monotonic()
        return max(0.0, end - self.started_at)

    @property
    def completed_count(self) -> int:
        """Number of collectors in a terminal state."""
        terminal_states = {
            "success", "completed", "warning", "partial",
            "error", "failed", "timeout", "skipped",
        }
        return sum(
            collector.status in terminal_states
            for collector in self.collectors.values()
        )

    def render(self) -> Text:
        """Build a compact progress summary."""
        total = len(self.collectors)
        completed = self.completed_count

        line = Text()
        line.append("Collectors ", style="muted")
        line.append(f"{completed}/{total}", style="heading")
        line.append("  ·  Elapsed ", style="muted")
        line.append(self._format_elapsed(self.elapsed), style="text")

        return line

    def _refresh(self) -> None:
        """Refresh the summary when a console is available."""
        if self.console is not None:
            self.console.print(self.render())

    @staticmethod
    def _format_elapsed(seconds: float) -> str:
        if seconds < 60:
            return f"{seconds:.1f}s"

        minutes, remainder = divmod(int(seconds), 60)
        return f"{minutes}m {remainder:02d}s"