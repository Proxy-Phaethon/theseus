"""Extractor dispatcher for Theseus.

Receives an identification Packet, selects all compatible extractors
for its accepted input-type flag, and returns their extraction Packets.
"""

from __future__ import annotations

from typing import Callable

from core.packets import Packet, PacketStatus

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
from extractors.email_headers import emailheadersextract
from extractors.message_id import messageidextract
from extractors.contact import contactextract
from extractors.calendar import calendarextract
from extractors.vcf import vcfextract

from extractors.git_repository import gitrepositoryextract
from extractors.git_commit import gitcommitextract
from extractors.package import packageextract
from extractors.sbom import sbomextract
from extractors.container import containerextract

from extractors.json import jsonextract
from extractors.xml import xmlextract
from extractors.csv import csvextract
from extractors.sqlite import sqliteextract
from extractors.config import configextract
from extractors.env import envextract
from extractors.registry import registryextract
from extractors.log import logextract
from extractors.browser import browserextract
from extractors.har import harextract

Extractor = Callable[[Packet], Packet]

EXTRACTORS: dict[str, list[Extractor]] = {
    "--url": [
        urlextract,
        redirectextract,
    ],

    "--domain": [
        domainextract,
        dnsextract,
    ],

    "--hostname": [
        hostnameextract,
    ],

    "--ip": [
        ipextract,
    ],

    "--cidr": [
        cidrextract,
    ],

    "--port": [
        portextract,
    ],

    "--mac-address": [
        macextract,
        bssidextract,
    ],

    "--asn": [
        asnextract,
    ],

    "--tls-host": [
        tlsextract,
    ],

    "--certificate": [
        certificateextract,
    ],

    "--http-message": [
        httpextract,
    ],

    "--html-document": [
        webpageextract,
    ],

    "--javascript-source": [
        javascriptextract,
    ],

    "--css-source": [
        cssextract,
    ],

    "--network-capture": [
        pcapextract,
        flowextract,
    ],

    "--file": [
        fileextract,
        hashextract,
        binaryextract,
    ],

    "--directory": [
        directoryextract,
    ],

    "--hash": [
        hashextract,
    ],

    "--binary-file": [
        binaryextract,
    ],

    "--pdf": [
        pdfextract,
        fileextract,
        hashextract,
        binaryextract,
    ],

    "--office-document": [
        officeextract,
        fileextract,
        hashextract,
        binaryextract,
    ],

    "--image": [
        imageextract,
        fileextract,
        hashextract,
        binaryextract,
    ],

    "--audio": [
        audioextract,
        fileextract,
        hashextract,
        binaryextract,
    ],

    "--video": [
        videoextract,
        fileextract,
        hashextract,
        binaryextract,
    ],

    "--archive": [
        archiveextract,
        fileextract,
        hashextract,
        binaryextract,
    ],

    "--font": [
        fontextract,
        fileextract,
        hashextract,
        binaryextract,
    ],

    "--shortcut": [
        shortcutextract,
        fileextract,
        hashextract,
        binaryextract,
    ],

    "--email": [
        emailextract,
        emailheadersextract,
        messageidextract,
    ],

    "--contact": [
        contactextract,
        vcfextract,
    ],

    "--calendar": [
        calendarextract,
    ],

    "--browser-profile": [
        browserextract,
    ],

    "--http-archive": [
        harextract,
    ],

    "--log": [
        logextract,
    ],

    "--registry-artefact": [
        registryextract,
    ],

    "--environment-file": [
        envextract,
    ],

    "--git-repository": [
        gitrepositoryextract,
    ],

    "--git-commit": [
        gitcommitextract,
    ],

    "--package-manifest": [
        packageextract,
    ],

    "--sbom-document": [
        sbomextract,
    ],

    "--container-artefact": [
        containerextract,
    ],

    "--json-document": [
        jsonextract,
        configextract,
    ],

    "--xml-document": [
        xmlextract,
    ],

    "--csv-document": [
        csvextract,
    ],

    "--sqlite-database": [
        sqliteextract,
    ],

    "--config-file": [
        configextract,
    ],
}

class Executor:
    """Dispatches identified inputs to all compatible extractors."""

    def __init__(self) -> None:
        self.extractors = EXTRACTORS

    def execute(self, report: Packet) -> list[Packet]:
        """Execute all extractors associated with an identified input."""

        if not isinstance(report, Packet):
            raise TypeError("Executor requires a Packet.")

        if report.status != PacketStatus.SUCCESS:
            raise ValueError(
                "Executor received an unsuccessful identification report."
            )

        if report.stage != "identification":
            raise ValueError(
                "Executor requires an identification Packet."
            )

        flag = report.metadata.get("flag")

        if not isinstance(flag, str):
            return [
                self._failure(
                    report,
                    status=PacketStatus.NOT_IMPLEMENTED,
                    code="missing_input_flag",
                    message="Identification Packet does not contain a valid flag.",
                )
            ]

        extractors = self.extractors.get(flag)

        if not extractors:
            return [
                self._failure(
                    report,
                    status=PacketStatus.NOT_IMPLEMENTED,
                    code="extractors_not_found",
                    message=f"No extractors are configured for input type '{flag}'.",
                )
            ]

        results: list[Packet] = []

        for extractor in extractors:
            try:
                result = extractor(report)

                if not isinstance(result, Packet):
                    raise TypeError(
                        f"Extractor '{extractor.__name__}' did not return a Packet."
                    )

                results.append(result)

            except Exception as exc:
                results.append(
                    self._failure(
                        report,
                        status=PacketStatus.FAILED,
                        code="extraction_failed",
                        message=str(exc),
                        component=extractor.__name__,
                    )
                )

        return results

    @staticmethod
    def _failure(
        report: Packet,
        *,
        status: PacketStatus,
        code: str,
        message: str,
        component: str = "core.executor",
    ) -> Packet:
        """Create a standardised extraction failure Packet."""

        response = report.child(
            stage="extraction",
            artefact_type=report.artefact_type,
            input=report.input,
            status=status,
        )

        response.add_error(
            code=code,
            message=message,
            component=component,
        )

        return response