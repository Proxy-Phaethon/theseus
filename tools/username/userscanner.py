import json
import subprocess
import tempfile
from pathlib import Path

class UserScannerTool:
    def __init__(self, timeout=300):
        self.timeout = timeout
        self.command = (
            Path(__file__).resolve().parents[2]
            / ".venv"
            / "bin"
            / "user-scanner"
        )

    def run(self, username):
        with tempfile.NamedTemporaryFile(
            suffix=".json",
            delete=False,
        ) as output:
            output_path = Path(output.name)

        try:
            subprocess.run(
                [
                    str(self.command),
                    "-u", username,
                    "--cross-scan",
                    "--cross-emails", "none",
                    "-f", "json",
                    "-o", str(output_path),
                ],
                capture_output=True,
                text=True,
                timeout=self.timeout,
                check=False,
            )

            with output_path.open(
                "r",
                encoding="utf-8",
            ) as file:
                records = json.load(file)

            return [
                {
                    "site": record["site_name"],
                    "category": record.get("category"),
                    "url": record["url"],
                    "source": "UserScannerTool",
                    "extra": record.get("extra", {}),
                }
                for record in records
                if record.get("status") == "Found"
                and record.get("url")
                and record.get("site_name")
            ]

        except (
            OSError,
            json.JSONDecodeError,
            subprocess.TimeoutExpired,
        ):
            return []

        finally:
            output_path.unlink(missing_ok=True)