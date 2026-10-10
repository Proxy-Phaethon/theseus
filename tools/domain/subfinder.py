import os
import subprocess

class SubfinderTool:
    def run(self, domain):
        gopath = subprocess.run(
            ["go", "env", "GOPATH"],
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()

        binary = os.path.join(gopath, "bin", "subfinder")

        result = subprocess.run(
            [
                binary,
                "-d", domain,
                "-silent",
            ],
            capture_output=True,
            text=True,
        )

        if result.returncode != 0:
            raise RuntimeError(result.stderr.strip())

        return result.stdout