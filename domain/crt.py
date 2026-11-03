import socket
import ssl
import hashlib
import requests

from datetime import datetime, timezone
from cryptography import x509
from cryptography.hazmat.primitives import serialization

CRT_ENDPOINT = "https://crt.sh/"
TIMEOUT = 15

FIELDS = (
    "certificate_common_name",
    "subject_alternative_names",
    "certificate_organisation",
    "certificate_issuer",
    "certificate_serial_number",
    "certificate_sha256_fingerprint",
    "public_key_fingerprint",
    "certificate_validity_dates",
    "previously_associated_hostnames",
    "certificate_transparency_entries",
)

def empty_data() -> dict:
    return {
        field: "none"
        for field in FIELDS
    }

def get_name_attribute(name, attribute):
    values = name.get_attributes_for_oid(attribute)

    if not values:
        return "none"

    return values[0].value

def format_datetime(value):
    if value is None:
        return "none"

    return value.astimezone(timezone.utc).isoformat()

def get_live_certificate(domain: str) -> dict:
    context = ssl.create_default_context()

    with socket.create_connection(
        (domain, 443),
        timeout=TIMEOUT
    ) as connection:

        with context.wrap_socket(
            connection,
            server_hostname=domain
        ) as secure_connection:

            certificate_der = secure_connection.getpeercert(
                binary_form=True
            )

    certificate = x509.load_der_x509_certificate(
        certificate_der
    )

    subject = certificate.subject
    issuer = certificate.issuer

    try:
        san_extension = certificate.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        )

        alternative_names = san_extension.value.get_values_for_type(
            x509.DNSName
        )

    except x509.ExtensionNotFound:
        alternative_names = []

    public_key_der = certificate.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return {
        "certificate_common_name": get_name_attribute(
            subject,
            x509.NameOID.COMMON_NAME
        ),

        "subject_alternative_names": sorted(
            set(alternative_names)
        ),

        "certificate_organisation": get_name_attribute(
            subject,
            x509.NameOID.ORGANIZATION_NAME
        ),

        "certificate_issuer": issuer.rfc4514_string(),

        "certificate_serial_number": format(
            certificate.serial_number,
            "X"
        ),

        "certificate_sha256_fingerprint": (
            certificate.fingerprint(
                __import__(
                    "cryptography.hazmat.primitives.hashes",
                    fromlist=["SHA256"]
                ).SHA256()
            ).hex(":").upper()
        ),

        "public_key_fingerprint": hashlib.sha256(
            public_key_der
        ).hexdigest(),

        "certificate_validity_dates": {
            "not_before": format_datetime(
                certificate.not_valid_before_utc
            ),
            "not_after": format_datetime(
                certificate.not_valid_after_utc
            )
        }
    }

def get_transparency_entries(domain: str) -> list:
    entries = {}

    queries = [
        domain,
        f"%.{domain}"
    ]

    for query in queries:
        try:
            response = requests.get(
                CRT_ENDPOINT,
                params={
                    "q": query,
                    "output": "json"
                },
                timeout=TIMEOUT
            )

            response.raise_for_status()

            records = response.json()

            if not isinstance(records, list):
                continue

            for record in records:
                entry_id = record.get("id")

                if not entry_id:
                    continue

                entries[str(entry_id)] = {
                    "id": entry_id,
                    "issuer_name": record.get("issuer_name"),
                    "common_name": record.get("common_name"),
                    "name_value": record.get("name_value"),
                    "not_before": record.get("not_before"),
                    "not_after": record.get("not_after"),
                    "entry_timestamp": record.get(
                        "entry_timestamp"
                    )
                }

        except (
            requests.RequestException,
            ValueError,
            TypeError
        ):
            continue

    return list(entries.values())

def extract_ct_hostnames(entries: list) -> set:
    hostnames = set()

    for entry in entries:
        names = entry.get("name_value")

        if not names:
            continue

        for hostname in names.splitlines():
            hostname = hostname.strip().lower().rstrip(".")

            if hostname:
                hostnames.add(hostname)

        common_name = entry.get("common_name")

        if common_name:
            common_name = common_name.strip().lower().rstrip(".")

            if common_name:
                hostnames.add(common_name)

    return hostnames

def run(domain: str) -> dict:
    data = empty_data()
    provenance = []
    related_entities = []
    errors = []

    try:
        certificate_data = get_live_certificate(domain)

        data.update(certificate_data)

        provenance.append({
            "source": f"https://{domain}",
            "method": "TLS certificate inspection",
            "retrieved_at": datetime.now(
                timezone.utc
            ).isoformat()
        })

    except Exception as exc:
        errors.append(
            f"Live certificate retrieval failed: {exc}"
        )

    try:
        ct_entries = get_transparency_entries(domain)

        if ct_entries:
            data["certificate_transparency_entries"] = ct_entries

            ct_hostnames = extract_ct_hostnames(ct_entries)

            current_sans = data.get(
                "subject_alternative_names",
                []
            )

            if current_sans == "none":
                current_sans = []

            current_sans = {
                hostname.lower().rstrip(".")
                for hostname in current_sans
            }

            current_cn = data.get("certificate_common_name")

            if current_cn != "none":
                current_sans.add(
                    current_cn.lower().rstrip(".")
                )

            data["previously_associated_hostnames"] = sorted(
                ct_hostnames - current_sans
            )

            related_entities.extend(
                {
                    "type": "hostname",
                    "value": hostname,
                    "relationship": "observed_in_certificate_transparency"
                }
                for hostname in sorted(ct_hostnames)
                if hostname != domain
            )

        provenance.append({
            "source": CRT_ENDPOINT,
            "method": "Certificate Transparency search",
            "retrieved_at": datetime.now(
                timezone.utc
            ).isoformat()
        })

    except Exception as exc:
        errors.append(
            f"Certificate Transparency retrieval failed: {exc}"
        )

    populated_fields = sum(
        1
        for value in data.values()
        if value != "none" and value != []
    )

    if errors and populated_fields:
        status = "partial"

    elif errors:
        status = "error"

    elif populated_fields == len(FIELDS):
        status = "success"

    elif populated_fields:
        status = "partial"

    else:
        status = "no_results"

    result = {
        "status": status,
        "module": "crt",
        "data": data,
        "provenance": provenance,
        "related_entities": related_entities
    }

    if errors:
        result["error"] = errors

    return result