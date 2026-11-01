from pathlib import Path
import hashlib

import vobject

from core.packets import Packet, PacketStatus

def _decode_value(value):
    """Convert vCard property values into JSON-compatible values."""
    if value is None:
        return None

    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")

    if isinstance(value, (str, int, float, bool)):
        return value

    if isinstance(value, (list, tuple)):
        return [_decode_value(item) for item in value]

    if hasattr(value, "isoformat"):
        try:
            return value.isoformat()
        except Exception:
            pass

    if hasattr(value, "__dict__"):
        return {
            key: _decode_value(item)
            for key, item in vars(value).items()
            if not key.startswith("_")
        }

    return str(value)

def _extract_parameters(property):
    params = getattr(property, "params", {})

    return {
        str(key): _decode_value(value)
        for key, value in params.items()
    }

def _extract_property(property):
    return {
        "name": property.name,
        "value": _decode_value(property.value),
        "parameters": _extract_parameters(property),
        "group": getattr(property, "group", None),
    }

def _extract_component(component):
    properties = {}

    for property in component.getChildren():
        name = property.name.upper()

        properties.setdefault(name, []).append(
            _extract_property(property)
        )

    return {
        "type": component.name.upper(),
        "properties": properties,
    }

def _extract_card(card):
    properties = {}

    for property in card.getChildren():
        name = property.name.upper()

        properties.setdefault(name, []).append(
            _extract_property(property)
        )

    return {
        "version": _decode_value(
            card.version.value if hasattr(card, "version") else None
        ),
        "properties": properties,
        "property_count": sum(
            len(values) for values in properties.values()
        ),
    }

def _hash_source(source):
    return {
        "md5": hashlib.md5(source).hexdigest(),
        "sha1": hashlib.sha1(source).hexdigest(),
        "sha256": hashlib.sha256(source).hexdigest(),
    }

def _parse_vcards(source):
    try:
        cards = list(vobject.readComponents(source))
    except Exception as exc:
        raise ValueError(
            f"Unable to parse vCard source: {exc}"
        ) from exc

    if not cards:
        raise ValueError("No vCard entries were found.")

    results = []

    for card in cards:
        if card.name.upper() != "VCARD":
            continue

        results.append(_extract_card(card))

    if not results:
        raise ValueError("No valid VCARD components were found.")

    return results

def vcfextract(packet: Packet) -> Packet:
    result = packet.child(
        stage="extraction",
        artefact_type="vcf",
        status=PacketStatus.RUNNING,
    )

    try:
        value = packet.input

        if not isinstance(value, str) or not value.strip():
            raise ValueError("vCard input must be a non-empty string.")

        candidate = value.strip()

        if "\n" in candidate or "\r" in candidate:
            raw_source = candidate.encode("utf-8", errors="replace")
            source_type = "raw_vcard"
            source_path = None

        else:
            path = Path(candidate)

            try:
                is_file = path.is_file()
            except OSError:
                is_file = False

            if not is_file:
                raise FileNotFoundError(
                    "vCard source file was not found."
                )

            if path.suffix.lower() != ".vcf":
                raise ValueError("Only .vcf files are supported.")

            raw_source = path.read_bytes()
            source_type = "file"
            source_path = str(path.resolve())

        source = raw_source.decode("utf-8-sig", errors="replace")
        cards = _parse_vcards(source)

        result.data = {
            "source": {
                "type": source_type,
                "path": source_path,
                "size_bytes": len(raw_source),
                "hashes": _hash_source(raw_source),
            },
            "cards": cards,
            "card_count": len(cards),
            "total_properties": sum(
                card["property_count"]
                for card in cards
            ),
        }

        result.status = PacketStatus.SUCCESS

    except FileNotFoundError as exc:
        result.status = PacketStatus.FAILED
        result.add_error(
            code="VCF_SOURCE_NOT_FOUND",
            message=str(exc),
            component="extractors.vcf",
        )

    except PermissionError:
        result.status = PacketStatus.FAILED
        result.add_error(
            code="VCF_PERMISSION_DENIED",
            message="Permission denied while reading the vCard source.",
            component="extractors.vcf",
        )

    except (ValueError, OSError) as exc:
        result.status = PacketStatus.FAILED
        result.add_error(
            code="VCF_INVALID_INPUT",
            message=str(exc),
            component="extractors.vcf",
        )

    except Exception as exc:
        result.status = PacketStatus.FAILED
        result.add_error(
            code="VCF_EXTRACTION_FAILED",
            message=str(exc),
            component="extractors.vcf",
        )

    return result