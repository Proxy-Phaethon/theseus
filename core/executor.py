"""Extractor dispatcher for Theseus.

Receives identification packets, dispatches them to the
appropriate extractor, and returns the extraction result.
"""

from __future__ import annotations

from typing import Callable

from core.packets import Packet, PacketStatus

# Extractor imports
from extractors.url import urlextract
from extractors.domain import domainextract
from extractors.dns import dnsextract
from extractors.ip import ipextract
from extractors.cidr import cidrextract
from extractors.hostname import hostnameextract
from extractors.redirect import redirectextract
from extractors.http import httpextract
from extractors.webpage import webpageextract
from extractors.javascript import javascriptextract
from extractors.css import cssextract
from extractors.asn import asnextract
from extractors.mac import macextract
from extractors.bssid import bssidextract
from extractors.port import portextract
from extractors.certificate import certificateextract
from extractors.tls import tlsextract
from extractors.pcap import pcapextract
from extractors.flow import flowextract
from extractors.file import fileextract
from extractors.hash import hashextract
from extractors.pdf import pdfextract
from extractors.office import officeextract
from extractors.image import imageextract
from extractors.audio import audioextract
from extractors.video import videoextract
from extractors.archive import archiveextract
from extractors.binary import binaryextract
from extractors.font import fontextract
from extractors.shortcut import shortcutextract
from extractors.directory import directoryextract
from extractors.email import emailextract

# Flag-to-extractor mapping
EXTRACTORS: dict[str, Callable[[Packet], Packet]] = {
    "--url": urlextract,
    "--domain": domainextract,
    "--dns": dnsextract,
    "--ip": ipextract,
    "--cidr": cidrextract,
    "--hostname": hostnameextract,
    "--redirect": redirectextract,
    "--http": httpextract,
    "--webpage": webpageextract,
    "--javascript": javascriptextract,
    "--css": cssextract,
    "--asn": asnextract,
    "--mac": macextract,
    "--bssid": bssidextract,
    "--port": portextract,
    "--certificate": certificateextract,
    "--tls": tlsextract,
    "--pcap": pcapextract,
    "--flow": flowextract,
    "--file": fileextract,
    "--hash": hashextract,
    "--pdf": pdfextract,
    "--office": officeextract,
    "--image": imageextract,
    "--audio": audioextract,
    "--video": videoextract,
    "--archive": archiveextract,
    "--binary": binaryextract,
    "--font": fontextract,
    "--shortcut": shortcutextract,
    "--directory": directoryextract,
    "--email": emailextract,
}

class Executor:
    """Dispatches identified inputs to their corresponding extractors."""

    def __init__(self) -> None:
        self.extractors = EXTRACTORS

    def execute(self, report: Packet) -> Packet:
        """Send an identification packet to its corresponding extractor."""

        if not isinstance(report, Packet):
            raise TypeError("Executor requires a Packet.")

        if report.status != PacketStatus.SUCCESS:
            raise ValueError(
                "Executor received an unsuccessful identification report."
            )

        flag = report.metadata.get("flag")

        extractor = self.extractors.get(flag)

        if extractor is None:
            return self._failure(
                report,
                status=PacketStatus.NOT_IMPLEMENTED,
                code="extractor_not_found",
                message=f"No extractor is configured for flag '{flag}'.",
            )

        try:
            result = extractor(report)

            if not isinstance(result, Packet):
                raise TypeError(
                    f"Extractor '{flag}' did not return a Packet."
                )

            return result

        except Exception as exc:
            return self._failure(
                report,
                status=PacketStatus.FAILED,
                code="extraction_failed",
                message=str(exc),
            )

    @staticmethod
    def _failure(
        report: Packet,
        *,
        status: PacketStatus,
        code: str,
        message: str,
    ) -> Packet:
        """Create a standardised extraction failure packet."""

        response = report.child(
            stage="extraction",
            artefact_type=report.artefact_type,
            input=report.input,
            status=status,
        )

        response.add_error(
            code=code,
            message=message,
            component="core.executor",
        )

        return response