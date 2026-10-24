
"""
Email address parsing and normalization for Theseus.

Responsibilities:
- Preserve the original input.
- Remove surrounding whitespace and obvious accidental punctuation.
- Separate the local part and domain.
- Normalize the domain's case and IDN representation.
- Identify role-based and disposable-looking patterns.
- Report transformations without claiming mailbox existence.

Syntax validation is handled separately by syntax.py.
"""

from __future__ import annotations

import unicodedata
from dataclasses import asdict, dataclass
from typing import Any

ROLE_BASED_LOCALS = {
    "abuse",
    "admin",
    "administrator",
    "billing",
    "contact",
    "help",
    "hello",
    "info",
    " enquiries",
    "jobs",
    "legal",
    "mail",
    "marketing",
    "noreply",
    "no-reply",
    "postmaster",
    "privacy",
    "sales",
    "security",
    "support",
    "webmaster",
}

DISPOSABLE_DOMAIN_HINTS = {
    "10minutemail.com",
    "guerrillamail.com",
    "mailinator.com",
    "tempmail.com",
    "throwawaymail.com",
    "yopmail.com",
}

@dataclass
class NormalizedEmail:
    original: str
    input_trimmed: str
    address: str | None
    local_part: str | None
    domain: str | None
    domain_ascii: str | None
    domain_unicode: str | None
    fully_qualified: str | None
    role_based: bool
    disposable_looking: bool
    special_use_domain: bool
    transformations: list[str]
    errors: list[str]

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable result."""
        return asdict(self)

SPECIAL_USE_DOMAINS = {
    "example",
    "invalid",
    "localhost",
    "test",
    "example.com",
    "example.net",
    "example.org",
    "test.com",
    "test.net",
    "test.org",
}

def _remove_accidental_punctuation(value: str) -> tuple[str, list[str]]:
    """
    Remove common wrapping punctuation introduced by copied text.

    Deliberately does not strip periods, plus signs, or other characters
    from the local part itself.
    """
    transformations = []
    cleaned = value

    wrappers = [
        ("<", ">"),
        ("(", ")"),
        ("[", "]"),
        ('"', '"'),
    ]

    for opening, closing in wrappers:
        if cleaned.startswith(opening) and cleaned.endswith(closing):
            cleaned = cleaned[1:-1].strip()
            transformations.append(
                f"Removed surrounding {opening}{closing} wrapper"
            )
            break

    if cleaned.endswith((",", ";")):
        cleaned = cleaned[:-1].rstrip()
        transformations.append("Removed trailing punctuation")

    return cleaned, transformations

def _normalize_domain(domain: str) -> tuple[str | None, str | None, str | None]:
    """
    Return (ASCII domain, Unicode domain, error).

    Python's built-in IDNA codec avoids an external dependency. Its IDNA
    behavior follows the built-in codec's IDNA implementation, which may
    differ from newer IDNA/UTS #46 processing.
    """
    if not domain:
        return None, None, "Domain is empty"

    domain_unicode = unicodedata.normalize("NFC", domain).lower()

    if domain_unicode.endswith("."):
        domain_unicode = domain_unicode[:-1]

    if not domain_unicode:
        return None, None, "Domain is empty"

    try:
        domain_ascii = domain_unicode.encode("idna").decode("ascii").lower()
    except (UnicodeError, ValueError):
        return None, None, "Domain could not be converted to IDNA/Punycode"

    if len(domain_ascii) > 253:
        return None, None, "Domain exceeds maximum length"

    labels = domain_ascii.split(".")
    if any(not label for label in labels):
        return None, None, "Domain contains an empty label"

    if any(len(label) > 63 for label in labels):
        return None, None, "Domain label exceeds maximum length"

    return domain_ascii, domain_unicode, None

def _is_special_use_domain(domain_ascii: str) -> bool:
    if domain_ascii in SPECIAL_USE_DOMAINS:
        return True

    return any(
        domain_ascii.endswith("." + reserved)
        for reserved in (
            "localhost",
            "invalid",
            "test",
            "example",
            "example.com",
            "example.net",
            "example.org",
        )
    )

def normalize_email(value: str) -> NormalizedEmail:
    """
    Parse and normalize an email address conservatively.

    This function does not establish syntactic validity, mailbox existence,
    deliverability, or current ownership. Those are separate investigations.
    """
    original = value if isinstance(value, str) else str(value)
    errors: list[str] = []
    transformations: list[str] = []

    trimmed = original.strip()

    if trimmed != original:
        transformations.append("Removed leading/trailing whitespace")

    candidate, punctuation_changes = _remove_accidental_punctuation(trimmed)
    transformations.extend(punctuation_changes)

    if not candidate:
        errors.append("Email address is empty")
        return NormalizedEmail(
            original=original,
            input_trimmed=trimmed,
            address=None,
            local_part=None,
            domain=None,
            domain_ascii=None,
            domain_unicode=None,
            fully_qualified=None,
            role_based=False,
            disposable_looking=False,
            special_use_domain=False,
            transformations=transformations,
            errors=errors,
        )

    at_positions = []
    quoted = False
    escaped = False

    for index, char in enumerate(candidate):
        if escaped:
            escaped = False
            continue

        if char == "\\" and quoted:
            escaped = True
            continue

        if char == '"':
            quoted = not quoted
        elif char == "@" and not quoted:
            at_positions.append(index)

    if len(at_positions) != 1:
        errors.append(
            "Expected exactly one @ separator outside quoted text"
        )
        return NormalizedEmail(
            original=original,
            input_trimmed=trimmed,
            address=candidate,
            local_part=None,
            domain=None,
            domain_ascii=None,
            domain_unicode=None,
            fully_qualified=None,
            role_based=False,
            disposable_looking=False,
            special_use_domain=False,
            transformations=transformations,
            errors=errors,
        )

    at_index = at_positions[0]
    local_part = candidate[:at_index]
    raw_domain = candidate[at_index + 1:]

    if not local_part:
        errors.append("Local part is empty")

    if not raw_domain:
        errors.append("Domain is empty")

    domain_ascii = None
    domain_unicode = None

    if raw_domain:
        domain_ascii, domain_unicode, domain_error = _normalize_domain(
            raw_domain
        )
        if domain_error:
            errors.append(domain_error)
        elif domain_ascii != raw_domain:
            transformations.append("Normalized domain representation")

    address = None
    fully_qualified = None

    if domain_ascii is not None and local_part:
        address = f"{local_part}@{domain_ascii}"
        fully_qualified = address

    local_for_classification = local_part.strip('"').lower()
    role_based = local_for_classification in ROLE_BASED_LOCALS

    disposable_looking = bool(
        domain_ascii and domain_ascii in DISPOSABLE_DOMAIN_HINTS
    )

    special_use_domain = bool(
        domain_ascii and _is_special_use_domain(domain_ascii)
    )

    return NormalizedEmail(
        original=original,
        input_trimmed=trimmed,
        address=address,
        local_part=local_part or None,
        domain=raw_domain or None,
        domain_ascii=domain_ascii,
        domain_unicode=domain_unicode,
        fully_qualified=fully_qualified,
        role_based=role_based,
        disposable_looking=disposable_looking,
        special_use_domain=special_use_domain,
        transformations=transformations,
        errors=errors,
    )

if __name__ == "__main__":
    import json

    print("Theseus Email Normalizer")
    print("Enter an address, or type 'q' to quit.\n")

    while True:
        try:
            target = input("email> ")
        except (EOFError, KeyboardInterrupt):
            print()
            break

        if target.strip().lower() in {"q", "quit", "exit", "bye"}:
            break

        result = normalize_email(target)
        print(json.dumps(result.to_dict(), indent=2, ensure_ascii=False))