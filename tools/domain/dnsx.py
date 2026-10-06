import subprocess

class DNSXTool:
    def run(self, domain):
        result = subprocess.run(
            [
                "dnsx",
                "-silent",
                "-a",
                "-aaaa",
                "-cname",
                "-ns",
                "-mx",
                "-txt",
                "-srv",
                "-ptr",
                "-soa",
                "-resp",
            ],
            input=domain,
            capture_output=True,
            text=True,
        )

        if result.returncode != 0:
            raise RuntimeError(result.stderr.strip())

        return result.stdout