from __future__ import annotations

from datetime import timezone

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from core.packets import Packet, PacketStatus

def certificateextract(packet: Packet) -> Packet:
    """Extract structured information from an X.509 certificate."""

    result = packet.child(
        stage="extraction",
        artefact_type="certificate",
        status=PacketStatus.RUNNING,
    )

    try:
        certificate_data = packet.input

        if isinstance(certificate_data, str):
            certificate_data = certificate_data.strip().encode("utf-8")

        if not isinstance(certificate_data, bytes):
            raise ValueError("Certificate input must be PEM or DER data.")

        if not certificate_data:
            raise ValueError("Certificate input cannot be empty.")

        if b"-----BEGIN CERTIFICATE-----" in certificate_data:
            certificate = x509.load_pem_x509_certificate(
                certificate_data
            )
            encoding = "PEM"
        else:
            certificate = x509.load_der_x509_certificate(
                certificate_data
            )
            encoding = "DER"

        def get_name(name):
            return [
                {
                    "oid": attribute.oid.dotted_string,
                    "name": attribute.oid._name,
                    "value": attribute.value,
                }
                for attribute in name
            ]

        def format_datetime(value):
            return value.astimezone(timezone.utc).isoformat()

        try:
            san_extension = certificate.extensions.get_extension_for_class(
                x509.SubjectAlternativeName
            )

            subject_alternative_names = [
                str(name)
                for name in san_extension.value
            ]

        except x509.ExtensionNotFound:
            subject_alternative_names = None

        try:
            basic_constraints = (
                certificate.extensions.get_extension_for_class(
                    x509.BasicConstraints
                ).value
            )

            constraints = {
                "is_ca": basic_constraints.ca,
                "path_length": basic_constraints.path_length,
            }

        except x509.ExtensionNotFound:
            constraints = None

        public_key = certificate.public_key()

        public_key_info = {
            "algorithm": type(public_key).__name__,
            "size": getattr(public_key, "key_size", None),
        }

        try:
            public_key_info["public_key_pem"] = (
                public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo,
                ).decode("utf-8")
            )
        except (AttributeError, ValueError):
            public_key_info["public_key_pem"] = None

        result.data = {
            "encoding": encoding,
            "version": certificate.version.name,
            "serial_number": str(certificate.serial_number),
            "signature_algorithm": certificate.signature_algorithm_oid._name,
            "signature_algorithm_oid": (
                certificate.signature_algorithm_oid.dotted_string
            ),
            "subject": get_name(certificate.subject),
            "issuer": get_name(certificate.issuer),
            "validity": {
                "not_before": format_datetime(certificate.not_valid_before_utc),
                "not_after": format_datetime(certificate.not_valid_after_utc),
            },
            "subject_alternative_names": subject_alternative_names,
            "basic_constraints": constraints,
            "public_key": public_key_info,
            "fingerprints": {
                "sha1": certificate.fingerprint(
                    __import__("cryptography").hazmat.primitives.hashes.SHA1()
                ).hex(),
                "sha256": certificate.fingerprint(
                    __import__("cryptography").hazmat.primitives.hashes.SHA256()
                ).hex(),
            },
        }

        result.status = PacketStatus.SUCCESS

    except Exception as exc:
        result.status = PacketStatus.FAILED
        result.add_error(
            code="certificate_extraction_failed",
            message=str(exc),
            component="extractors.certificate",
        )

    return result