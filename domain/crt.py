import socket
import ssl
import hashlib
import requests

from datetime import datetime, timezone
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization

CRT_ENDPOINT = "https://crt.sh/"
TIMEOUT = 15

MODULE_NAME = "crt"

FIELDS = (
    "certificate_common_name",
    "subject_alternative_names",
    "certificate_organisation",
    "certificate_issuer",
    "certificate_serial_number",
    "certificate_sha256_fingerprint",
    "public_key_fingerprint",
    "certificate_validity_dates",
    "certificate_transparency_hostnames",
    "certificate_transparency_entries",
)

def empty_data() -> dict:
    return {
        "certificate_common_name": None,
        "subject_alternative_names": [],
        "certificate_organisation": None,
        "certificate_issuer": None,
        "certificate_serial_number": None,
        "certificate_sha256_fingerprint": None,
        "public_key_fingerprint": None,
        "certificate_validity_dates": None,
        "certificate_transparency_hostnames": [],
        "certificate_transparency_entries": [],
    }

def get_name_attribute(name, attribute):
    values = name.get_attributes_for_oid(attribute)

    if not values:
        return None

    return values[0].value

def format_datetime(value):
    if value is None:
        return None

    return value.astimezone(timezone.utc).isoformat()

def get_live_certificate(domain: str) -> dict:
    context = ssl.create_default_context()

    with socket.create_connection(
        (domain, 443),
        timeout=TIMEOUT,
    ) as connection:

        with context.wrap_socket(
            connection,
            server_hostname=domain,
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
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    return {
        "certificate_common_name": get_name_attribute(
            subject,
            x509.NameOID.COMMON_NAME,
        ),

        "subject_alternative_names": sorted(
            set(alternative_names)
        ),

        "certificate_organisation": get_name_attribute(
            subject,
            x509.NameOID.ORGANIZATION_NAME,
        ),

        "certificate_issuer": issuer.rfc4514_string(),

        "certificate_serial_number": format(
            certificate.serial_number,
            "X",
        ),

        "certificate_sha256_fingerprint": (
            certificate.fingerprint(
                hashes.SHA256()
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
            ),
        },
    }

def get_transparency_entries(domain: str) -> tuple[list, list, bool]:
    entries = {}
    errors = []
    successful_queries = 0

    queries = [
        domain,
        f"%.{domain}",
    ]

    for query in queries:
        try:
            response = requests.get(
                CRT_ENDPOINT,
                params={
                    "q": query,
                    "output": "json",
                },
                timeout=TIMEOUT,
            )

            response.raise_for_status()
            records = response.json()

            if not isinstance(records, list):
                raise ValueError(
                    "Unexpected Certificate Transparency response."
                )

            successful_queries += 1

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
                    "entry_timestamp": record.get("entry_timestamp"),
                }

        except (
            requests.RequestException,
            ValueError,
            TypeError,
        ) as exc:
            errors.append(
                f"Certificate Transparency query failed ({query}): {exc}"
            )

    return (
        list(entries.values()),
        errors,
        successful_queries > 0,
    )

def extract_ct_hostnames(entries: list) -> set:
    hostnames = set()

    for entry in entries:
        names = entry.get("name_value")

        if names:
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

def has_data(value) -> bool:
    if value is None:
        return False

    if isinstance(value, (list, dict, tuple, set)):
        return bool(value)

    return True

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
            ).isoformat(),
        })

    except Exception as exc:
        errors.append(
            f"Live certificate retrieval failed: {exc}"
        )

    try:
        ct_entries, ct_errors, query_succeeded = (
            get_transparency_entries(domain)
        )

        errors.extend(ct_errors)

        if query_succeeded:
            provenance.append({
                "source": CRT_ENDPOINT,
                "method": "Certificate Transparency search",
                "retrieved_at": datetime.now(
                    timezone.utc
                ).isoformat(),
            })

        if ct_entries:
            data["certificate_transparency_entries"] = ct_entries

            ct_hostnames = extract_ct_hostnames(ct_entries)

            data["certificate_transparency_hostnames"] = sorted(
                ct_hostnames
            )

            for hostname in sorted(ct_hostnames):
                if hostname == domain:
                    continue

                related_entities.append({
                    "type": "hostname",
                    "value": hostname,
                    "relationship": (
                        "observed_in_certificate_transparency"
                    ),
                })

    except Exception as exc:
        errors.append(
            f"Certificate Transparency retrieval failed: {exc}"
        )

    populated_fields = sum(
        has_data(value)
        for value in data.values()
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

    return {
        "module": MODULE_NAME,
        "status": status,
        "data": data,
        "provenance": provenance,
        "related_entities": related_entities,
        "errors": errors,
    }