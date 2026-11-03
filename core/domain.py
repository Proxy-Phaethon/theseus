import importlib
from urllib.parse import urlsplit
import ipaddress

class DomainExecutor:

    MODULES = (
        "identity",
        "geography",
        "network",
        "hostname",
        "crt",
        "email",
        "website",
        "history",
        "technical"
    )

    @staticmethod
    def extract_domain(value: str) -> str:
        """
        Extract and normalise a domain from a bare domain
        or a URL.
        """

        if not isinstance(value, str) or not value.strip():
            raise ValueError("No valid input provided.")

        value = value.strip()

        if "://" in value:
            parsed = urlsplit(value)

            if parsed.scheme.lower() not in ("http", "https"):
                raise ValueError("Unsupported URL scheme.")

            if not parsed.hostname:
                raise ValueError("Unable to extract hostname from URL.")

            domain = parsed.hostname

        else:
            domain = value

        domain = domain.rstrip(".").lower()

        try:
            ipaddress.ip_address(domain)
            raise ValueError("IP addresses are not supported.")
        except ValueError as exc:
            if str(exc) == "IP addresses are not supported.":
                raise

        return domain

    @classmethod
    def execute_modules(cls, domain: str) -> dict:
        """
        Execute all domain modules independently.
        Collect their respective envelopes.
        """

        results = {}

        for module_name in cls.MODULES:

            try:
                module = importlib.import_module(
                    f"domain.{module_name}"
                )

                result = module.run(domain)

                results[module_name] = result

            except Exception as exc:

                results[module_name] = {
                    "status": "error",
                    "module": module_name,
                    "data": {},
                    "provenance": [],
                    "related_entities": [],
                    "error": str(exc)
                }

        return results

    @classmethod
    def process(cls, input_data):

        if isinstance(input_data, dict):

            if not input_data.get("success"):
                raise ValueError(
                    input_data.get("message", "Input identification failed.")
                )

            value = input_data.get("input")

        else:
            value = input_data

        domain = cls.extract_domain(value)

        module_results = cls.execute_modules(domain)

        response_payload = {
            "domain": domain,
            "modules": module_results
        }

        from core import responder

        return responder.respond(response_payload)

def process(input_data):
    """Public entry point for the domain executor."""
    return DomainExecutor.process(input_data)