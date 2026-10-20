import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

class MaigretTool:
    def __init__(self, timeout=300):
        self.timeout = timeout

    def run(self, username):
        executable = shutil.which("maigret")

        if executable is None:
            candidate = Path(sys.executable).parent / "maigret"
            if candidate.is_file():
                executable = str(candidate)
            else:
                raise RuntimeError(
                    "Maigret executable not found. "
                    "Install Maigret in the active Python environment."
                )

        with tempfile.TemporaryDirectory(prefix="theseus-maigret-") as temp_dir:
            output_dir = Path(temp_dir)

            command = [
                executable,
                username,
                "--no-autoupdate",
                "--no-recursion",
                "--no-progressbar",
                "--no-color",
                "-J",
                "simple",
            ]

            try:
                process = subprocess.run(
                    command,
                    cwd=output_dir,
                    capture_output=True,
                    text=True,
                    timeout=self.timeout,
                    check=False,
                )
            except subprocess.TimeoutExpired as exc:
                raise RuntimeError(
                    f"Maigret timed out while scanning {username!r}."
                ) from exc

            report_path = (
                output_dir
                / "reports"
                / f"report_{username}_simple.json"
            )

            if not report_path.is_file():
                details = (process.stderr or process.stdout).strip()
                raise RuntimeError(
                    f"Maigret failed to produce a report for {username!r}. "
                    f"Exit code: {process.returncode}. {details}"
                )

            try:
                data = json.loads(report_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                raise RuntimeError(
                    f"Could not read Maigret's report for {username!r}."
                ) from exc

            if not isinstance(data, dict):
                raise RuntimeError("Maigret returned an unexpected report format.")

            results = []

            for record in data.values():
                if not isinstance(record, dict):
                    continue

                status = record.get("status", {})

                if not isinstance(status, dict):
                    continue

                if status.get("status") != "Claimed":
                    continue

                site = status.get("site_name")
                url = status.get("url")

                if not site or not url:
                    continue

                tags = status.get("tags", [])
                ids = status.get("ids", {})

                results.append(
                    {
                        "site": site,
                        "category": ", ".join(tags) if tags else None,
                        "url": url,
                        "source": "MaigretTool",
                        "extra": ids if isinstance(ids, dict) else {},
                    }
                )

            return results