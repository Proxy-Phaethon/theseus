import json
import shutil
import subprocess

class TLSXTool:
    def __init__(self) -> None:
        if shutil.which("tlsx") is None:
            raise RuntimeError(
                "tlsx is not installed or not in PATH"
            )

    def run(self, ip: str) -> dict:
        result = subprocess.run(
            [
                "tlsx",
                "-silent",
                "-json",
            ],
            input=f"{ip}\n",
            capture_output=True,
            text=True,
            timeout=30,
            check=True,
        )

        results = []

        for line in result.stdout.splitlines():
            line = line.strip()

            if not line:
                continue

            results.append(json.loads(line))

        return {
            "ip": ip,
            "results": results,
        }