import os
import subprocess

class AssetfinderTool:
    def run(self, domain):
        gopath = subprocess.run(
            ["go", "env", "GOPATH"],
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()

        binary = os.path.join(gopath, "bin", "assetfinder")

        result = subprocess.run(
            [binary, "--subs-only", domain],
            capture_output=True,
            text=True,
        )

        if result.returncode != 0:
            raise RuntimeError(result.stderr.strip())

        return result.stdout