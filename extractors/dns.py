from __future__ import annotations

import dns.exception
import dns.resolver

from core.packets import Packet, PacketStatus

RECORD_TYPES = (
    "A",
    "AAAA",
    "CNAME",
    "MX",
    "NS",
    "TXT",
    "SOA",
)

def dnsextract(packet: Packet) -> Packet:
    """Retrieve DNS records associated with a domain name."""

    result = packet.child(
        stage="extraction",
        artefact_type="dns",
        status=PacketStatus.RUNNING,
    )

    try:
        if not isinstance(packet.input, str):
            raise ValueError("DNS input must be a string.")

        domain = packet.input.strip().rstrip(".").lower()

        if not domain:
            raise ValueError("Domain input cannot be empty.")

        domain = domain.encode("idna").decode("ascii")

        resolver = dns.resolver.Resolver()
        resolver.timeout = 3.0
        resolver.lifetime = 5.0

        records = {}
        successful_queries = 0
        failed_queries = 0

        for record_type in RECORD_TYPES:
            try:
                answer = resolver.resolve(
                    domain,
                    record_type,
                    raise_on_no_answer=False,
                )

                records[record_type] = [
                    record.to_text()
                    for record in answer
                ]

                successful_queries += 1

            except dns.resolver.NXDOMAIN:
                raise ValueError(
                    f"The domain '{domain}' does not exist."
                )

            except dns.resolver.NoAnswer:
                records[record_type] = []
                successful_queries += 1

            except (
                dns.resolver.NoNameservers,
                dns.exception.Timeout,
            ) as exc:
                records[record_type] = []
                failed_queries += 1

                result.add_error(
                    code=f"dns_{record_type.lower()}_lookup_failed",
                    message=str(exc),
                    component="extractors.dns",
                )

        result.data = {
            "domain": domain,
            "records": records,
        }

        if failed_queries and successful_queries:
            result.status = PacketStatus.PARTIAL_SUCCESS

        elif failed_queries:
            result.status = PacketStatus.FAILED

        else:
            result.status = PacketStatus.SUCCESS

    except Exception as exc:
        result.status = PacketStatus.FAILED
        result.add_error(
            code="dns_extraction_failed",
            message=str(exc),
            component="extractors.dns",
        )

    return result