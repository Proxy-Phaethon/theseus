import json
import subprocess
import tempfile
from pathlib import Path

class UserScannerTool:
    def run(self, email):
        email = email.strip()

        with tempfile.TemporaryDirectory(prefix="theseus_user_scanner_") as temp_dir:
            output_path = Path(temp_dir) / "results.json"

            process = subprocess.run(
                [
                    "user-scanner",
                    "-e",
                    email,
                    "-f",
                    "json",
                    "-o",
                    str(output_path),
                ],
                capture_output=True,
                text=True,
                timeout=300,
                check=False,
            )

            if process.returncode != 0:
                raise RuntimeError(
                    "User Scanner failed "
                    f"(exit code {process.returncode}): "
                    f"{process.stderr.strip() or process.stdout.strip()}"
                )

            if not output_path.exists():
                raise RuntimeError(
                    "User Scanner completed without producing a JSON report."
                )

            with output_path.open(encoding="utf-8") as file:
                results = json.load(file)

            if not isinstance(results, list):
                raise ValueError("User Scanner returned an unexpected JSON structure.")

            return results