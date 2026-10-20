import csv
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

class SherlockTool:
    def __init__(self, timeout=10, scan_timeout=600, include_nsfw=False):
        self.timeout = timeout
        self.scan_timeout = scan_timeout
        self.include_nsfw = include_nsfw

    def run(self, username):
        executable = shutil.which("sherlock")

        if executable is None:
            candidate = Path(sys.executable).parent / "sherlock"
            if candidate.is_file():
                executable = str(candidate)
            else:
                raise RuntimeError(
                    "Sherlock executable not found in the active environment."
                )

        with tempfile.TemporaryDirectory(prefix="theseus-sherlock-") as temp_dir:
            output_dir = Path(temp_dir)

            command = [
                executable,
                username,
                "--local",
                "--no-color",
                "--timeout",
                str(self.timeout),
                "--csv",
                "--folderoutput",
                str(output_dir),
            ]

            if self.include_nsfw:
                command.append("--nsfw")

            try:
                process = subprocess.run(
                    command,
                    capture_output=True,
                    text=True,
                    timeout=self.scan_timeout,
                    check=False,
                )
            except subprocess.TimeoutExpired as exc:
                raise RuntimeError(
                    f" Sherlock timed out while scanning {username!r}."
                ) from exc

            reports = list(output_dir.glob("*.csv"))

            if not reports:
                details = (process.stderr or process.stdout).strip()
                raise RuntimeError(
                    f"Sherlock did not produce a CSV report for {username!r}. "
                    f"Exit code: {process.returncode}. {details}"
                )

            results = []

            try:
                with reports[0].open(
                    "r", encoding="utf-8-sig", newline=""
                ) as file:
                    reader = csv.DictReader(file)

                    required_fields = {
                        "name",
                        "url_user",
                        "exists",
                        "http_status",
                    }
                    if not required_fields.issubset(reader.fieldnames or []):
                        raise RuntimeError(
                            "Sherlock CSV has an unexpected column layout."
                        )

                    for row in reader:
                        if row.get("exists", "").lower() != "claimed":
                            continue

                        site = row.get("name")
                        url = row.get("url_user")

                        if not site or not url:
                            continue

                        results.append(
                            {
                                "site": site,
                                "category": None,
                                "url": url,
                                "source": "SherlockTool",
                                "extra": {
                                    "http_status": row.get("http_status"),
                                    "response_time_s": row.get("response_time_s"),
                                    "url_main": row.get("url_main"),
                                },
                            }
                        )
            except OSError as exc:
                raise RuntimeError(
                    f"Could not read Sherlock's CSV report for {username!r}."
                ) from exc

            if process.returncode != 0 and not results:
                details = (process.stderr or process.stdout).strip()
                raise RuntimeError(
                    f"Sherlock exited with code {process.returncode}. {details}"
                )

            return results