from urllib.parse import urlsplit
import ipaddress
import re

class Identifier:

    @staticmethod
    def identify(value: str) -> dict:

        if not isinstance(value, str) or not value.strip():
            return {
                "success": False,
                "message": "Input cannot be empty."
            }

        value = value.strip()

        if "://" in value:
            try:
                parsed = urlsplit(value)

                if parsed.scheme.lower() not in ("http", "https"):
                    return {
                        "success": False,
                        "message": "Unsupported URL scheme."
                    }

                if not parsed.netloc or not parsed.hostname:
                    return {
                        "success": False,
                        "message": "Malformed URL."
                    }

                hostname = parsed.hostname

            except ValueError:
                return {
                    "success": False,
                    "message": "Malformed URL."
                }

        else:
            hostname = value

        try:
            ipaddress.ip_address(hostname)
            return {
                "success": False,
                "message": "IP addresses are not supported by the domain tool."
            }
        except ValueError:
            pass

        hostname = hostname.rstrip(".").lower()

        if len(hostname) > 253:
            return {
                "success": False,
                "message": "Domain exceeds maximum length."
            }

        labels = hostname.split(".")

        if len(labels) < 2:
            return {
                "success": False,
                "message": "A fully qualified domain is required."
            }

        label_pattern = re.compile(
            r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$"
        )

        if not all(label_pattern.fullmatch(label) for label in labels):
            return {
                "success": False,
                "message": "Invalid domain format."
            }

        return {
            "success": True,
            "input": value,
            "input_type": "url" if "://" in value else "domain",
            "domain": hostname
        }