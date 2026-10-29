"""Standalone task progress display for Theseus."""

from __future__ import annotations

from dataclasses import dataclass, field
from time import monotonic

from rich.console import Console, Group, RenderableType
from rich.live import Live
from rich.panel import Panel
from rich.spinner import Spinner
from rich.table import Table
from rich.text import Text

from ui.status import format_status, normalize_status, print_task_status
from ui.theme import status_style

TERMINAL_STATUSES = {
    "success",
    "completed",
    "partial",
    "partial_success",
    "warning",
    "error",
    "failed",
    "failure",
    "timeout",
    "skipped",
    "not_supported",
    "not_implemented",
}

@dataclass
class TaskProgress:
    """Display state for one pipeline task."""

    name: str
    status: str = "pending"
    message: str = ""
    started_at: float | None = None
    finished_at: float | None = None

    @property
    def elapsed(self) -> float:
        """Return elapsed task time in seconds."""
        if self.started_at is None:
            return 0.0

        end = self.finished_at or monotonic()
        return max(0.0, end - self.started_at)

@dataclass
class ProgressDisplay:
    """Manage progress state and render it independently of main.py."""

    console: Console
    animate: bool = True
    tasks: dict[str, TaskProgress] = field(default_factory=dict)
    started_at: float | None = None
    finished_at: float | None = None

    _live: Live | None = field(default=None, init=False, repr=False)

    def start(self) -> None:
        """Start the progress display."""
        if self.started_at is not None:
            return

        self.started_at = monotonic()

        if self.animate:
            self._live = Live(
                self.render(),
                console=self.console,
                auto_refresh=True,
                refresh_per_second=8,
                transient=False,
            )
            self._live.start()

    def register(self, name: str, message: str = "") -> None:
        """Register a task before execution begins."""
        if name not in self.tasks:
            self.tasks[name] = TaskProgress(
                name=name,
                message=message,
            )
        else:
            self.tasks[name].message = message

        self._refresh()

    def update(
        self,
        name: str,
        status: str,
        message: str = "",
    ) -> None:
        """Apply an explicit task lifecycle update."""
        normalized = normalize_status(status)

        if name not in self.tasks:
            self.register(name)

        task = self.tasks[name]
        previous_status = task.status

        if normalized == "running" and task.started_at is None:
            task.started_at = monotonic()

        if normalized in TERMINAL_STATUSES:
            if task.started_at is None and normalized not in {
                "skipped",
                "not_supported",
                "not_implemented",
            }:
                task.started_at = monotonic()

            if task.finished_at is None:
                task.finished_at = monotonic()

        task.status = normalized
        task.message = message

        if not self.animate and previous_status != normalized:
            print_task_status(
                self.console,
                name,
                normalized,
                message,
            )

        self._refresh()

    def start_task(self, name: str, message: str = "") -> None:
        """Mark a task as running."""
        self.update(name, "running", message)

    def complete(self, name: str, message: str = "") -> None:
        """Mark a task as successful."""
        self.update(name, "success", message)

    def partial(self, name: str, message: str = "") -> None:
        """Mark a task as partially successful."""
        self.update(name, "partial_success", message)

    def fail(self, name: str, message: str = "") -> None:
        """Mark a task as failed."""
        self.update(name, "failed", message)

    def skip(self, name: str, message: str = "") -> None:
        """Mark a task as skipped."""
        self.update(name, "skipped", message)

    def finish(self) -> float:
        """Finish the display and return total elapsed time."""
        if self.finished_at is None:
            self.finished_at = monotonic()

        self._refresh()

        if self._live is not None:
            self._live.stop()
            self._live = None

        return self.elapsed

    @property
    def elapsed(self) -> float:
        """Return total elapsed time, frozen after finish()."""
        if self.started_at is None:
            return 0.0

        end = self.finished_at or monotonic()
        return max(0.0, end - self.started_at)

    @property
    def completed_count(self) -> int:
        """Count tasks in terminal states."""
        return sum(
            task.status in TERMINAL_STATUSES
            for task in self.tasks.values()
        )

    @property
    def total_count(self) -> int:
        return len(self.tasks)

    def render(self) -> RenderableType:
        """Build the current progress view."""
        summary = Table.grid(padding=(0, 2))
        summary.add_column(style="muted", no_wrap=True)
        summary.add_column(style="text")

        summary.add_row(
            "Tasks",
            f"{self.completed_count}/{self.total_count} complete",
        )
        summary.add_row("Elapsed", self._format_elapsed(self.elapsed))

        sections: list[RenderableType] = [summary]

        if self.tasks:
            table = Table(
                show_header=True,
                header_style="muted",
                expand=True,
                padding=(0, 1),
            )
            table.add_column("Task", style="target", ratio=3)
            table.add_column("Status", no_wrap=True)
            table.add_column("Elapsed", justify="right", no_wrap=True)
            table.add_column("Details", ratio=4, overflow="fold")

            for task in self.tasks.values():
                status_renderable = format_status(task.status)

                table.add_row(
                    task.name,
                    status_renderable,
                    self._format_elapsed(task.elapsed),
                    task.message or "",
                )

            sections.append(table)

        if self.animate and self.finished_at is None:
            sections.insert(
                0,
                Spinner("dots", text=Text(" Processing", style="running")),
            )

        return Panel(
            Group(*sections),
            title="THESEUS / PROGRESS",
            title_align="left",
            border_style="border",
            padding=(1, 2),
            expand=True,
        )

    def _refresh(self) -> None:
        """Refresh the live view when active."""
        if self._live is not None:
            self._live.update(self.render(), refresh=True)

    @staticmethod
    def _format_elapsed(seconds: float) -> str:
        if seconds < 60:
            return f"{seconds:.1f}s"

        minutes, remainder = divmod(int(seconds), 60)
        return f"{minutes}m {remainder:02d}s"