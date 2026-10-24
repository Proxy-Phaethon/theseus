"""
Email syntax validation for Theseus.

Checks whether an email address is structurally plausible.
Does not verify mailbox existence, deliverability, or ownership.
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from typing import Any

@dataclass
class EmailSyntaxResult:
    address: str
    valid: bool
    local_part: str | None
    domain: str | None
    internationalized: bool
    smtp_utf8_required: bool
    checks: dict[str, bool]
    errors: list[str]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

ATEXT = r"A-Za-z0-9!#$%&'*+/=?^_`{|}~-"
DOT_ATOM_RE = re.compile(rf"^[{ATEXT}]+(?:\.[{ATEXT}]+)*$")

DOMAIN_LABEL_RE = re.compile(
    r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$"
)

def _split_address(address: str) -> tuple[str | None, str | None]:
    """Split on the @ outside quoted local-part text."""
    quoted = False
    escaped = False
    separators: list[int] = []

    for index, char in enumerate(address):
        if escaped:
            escaped = False
            continue

        if char == "\\" and quoted:
            escaped = True
            continue

        if char == '"':
            quoted = not quoted
        elif char == "@" and not quoted:
            separators.append(index)

    if quoted or len(separators) != 1:
        return None, None

    position = separators[0]
    return address[:position], address[position + 1:]

def _valid_quoted_local(local: str) -> bool:
    """Validate a quoted-string local part conservatively."""
    if len(local) < 2 or local[0] != '"' or local[-1] != '"':
        return False

    inner = local[1:-1]
    escaped = False

    for char in inner:
        code = ord(char)

        if escaped:
            if code < 32 or code == 127:
                return False
            escaped = False
            continue

        if char == "\\":
            escaped = True
            continue

        if char == '"':
            return False

        if code < 32 or code == 127:
            return False

    return not escaped

def _valid_domain(domain: str) -> bool:
    """
    Validate a domain supplied in ASCII or Unicode form.

    Unicode labels are converted to IDNA for DNS hostname checks.
    A trailing root dot is accepted.
    """
    if not domain:
        return False

    candidate = domain[:-1] if domain.endswith(".") else domain
    if not candidate or len(candidate) > 253:
        return False

    try:
        ascii_domain = candidate.encode("idna").decode("ascii")
    except (UnicodeError, ValueError):
        return False

    labels = ascii_domain.split(".")
    if any(not label or len(label) > 63 for label in labels):
        return False

    return all(DOMAIN_LABEL_RE.fullmatch(label) for label in labels)

def validate_email_syntax(address: str) -> EmailSyntaxResult:
    """
    Validate email syntax without performing network requests.

    This is a practical validator, not a complete implementation of every
    historical RFC mailbox form. SMTPUTF8 is reported when non-ASCII
    characters occur in the local part.
    """
    original = address if isinstance(address, str) else str(address)
    errors: list[str] = []

    checks = {
        "no_surrounding_whitespace": original == original.strip(),
        "single_at_separator": False,
        "local_part_present": False,
        "domain_present": False,
        "local_part_syntax": False,
        "domain_syntax": False,
        "local_part_length": False,
        "address_length": False,
    }

    if original != original.strip():
        errors.append("Address contains leading or trailing whitespace")

    local, domain = _split_address(original)

    if local is None or domain is None:
        errors.append("Expected exactly one @ separator outside quoted text")
        return EmailSyntaxResult(
            address=original,
            valid=False,
            local_part=None,
            domain=None,
            internationalized=not original.isascii(),
            smtp_utf8_required=not original.isascii(),
            checks=checks,
            errors=errors,
        )

    checks["single_at_separator"] = True
    checks["local_part_present"] = bool(local)
    checks["domain_present"] = bool(domain)

    if not local:
        errors.append("Local part is empty")

    if not domain:
        errors.append("Domain is empty")

    local_bytes = local.encode("utf-8")
    checks["local_part_length"] = len(local_bytes) <= 64

    if not checks["local_part_length"]:
        errors.append("Local part exceeds 64 UTF-8 octets")

    if local.startswith('"') or local.endswith('"'):
        local_valid = _valid_quoted_local(local)
    else:
        if local.isascii():
            local_valid = bool(DOT_ATOM_RE.fullmatch(local))
        else:
            local_valid = (
                not local.startswith(".")
                and not local.endswith(".")
                and ".." not in local
                and not any(
                    char.isspace() or ord(char) < 32 or ord(char) == 127
                    for char in local
                )
                and "@" not in local
            )

    checks["local_part_syntax"] = local_valid

    if not local_valid:
        errors.append("Local part has invalid or unsupported syntax")

    domain_valid = _valid_domain(domain)
    checks["domain_syntax"] = domain_valid

    if not domain_valid:
        errors.append("Domain is not a valid DNS hostname")

    address_length = len(original.encode("utf-8"))
    checks["address_length"] = address_length <= 254

    if not checks["address_length"]:
        errors.append("Address exceeds 254 UTF-8 octets")

    internationalized = not original.isascii()
    smtp_utf8_required = not local.isascii()

    valid = all(checks.values())

    return EmailSyntaxResult(
        address=original,
        valid=valid,
        local_part=local,
        domain=domain,
        internationalized=internationalized,
        smtp_utf8_required=smtp_utf8_required,
        checks=checks,
        errors=errors,
    )

if __name__ == "__main__":
    import json

    print("Theseus Email Syntax Validator")
    print("Enter an address, or type 'q' to quit.\n")

    while True:
        try:
            target = input("email> ")
        except (EOFError, KeyboardInterrupt):
            print()
            break

        if target.strip().lower() in {"q", "quit", "exit", "bye"}:
            break

        result = validate_email_syntax(target)
        print(json.dumps(result.to_dict(), indent=2, ensure_ascii=False))