import json
import shutil
import subprocess
import tempfile
from pathlib import Path

class EnolaTool:
    def __init__(self, timeout=300):
        self.timeout = timeout

    def _find_executable(self):
        executable = shutil.which("enola")
        if executable:
            return executable

        go = shutil.which("go")
        if not go:
            raise RuntimeError("Enola executable and Go were not found.")

        result = subprocess.run(
            [go, "env", "GOPATH"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )

        if result.returncode != 0:
            raise RuntimeError("Could not determine the Go GOPATH.")

        candidate = Path(result.stdout.strip()) / "bin" / "enola"
        if candidate.is_file():
            return str(candidate)

        raise RuntimeError(
            "Enola executable not found. Install it with "
            "'go install github.com/theyahya/enola/cmd/enola@latest'."
        )

    def run(self, username):
        executable = self._find_executable()

        with tempfile.TemporaryDirectory(prefix="theseus-enola-") as temp_dir:
            output_path = Path(temp_dir) / "results.json"

            command = [
                executable,
                username,
                "--output",
                str(output_path),
            ]

            try:
                process = subprocess.run(
                    command,
                    capture_output=True,
                    text=True,
                    timeout=self.timeout,
                    check=False,
                )
            except subprocess.TimeoutExpired as exc:
                raise RuntimeError(
                    f"Enola timed out while scanning {username!r}."
                ) from exc

            if process.returncode != 0:
                details = (process.stderr or process.stdout).strip()
                raise RuntimeError(
                    f"Enola failed for {username!r} "
                    f"(exit code {process.returncode}): {details}"
                )

            if not output_path.is_file():
                raise RuntimeError(
                    f"Enola did not produce a JSON report for {username!r}."
                )

            try:
                data = json.loads(output_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                raise RuntimeError("Could not read Enola's JSON report.") from exc

            if not isinstance(data, list):
                raise RuntimeError("Enola returned an unexpected report format.")

            results = []

            for record in data:
                if not isinstance(record, dict) or record.get("found") is not True:
                    continue

                site = record.get("title")
                url = record.get("url")

                if not site or not url:
                    continue

                results.append(
                    {
                        "site": site,
                        "category": None,
                        "url": url,
                        "source": "EnolaTool",
                        "extra": {},
                    }
                )

            return results