from pathlib import Path
import hashlib
from datetime import datetime, timezone

from fontTools.ttLib import TTFont, TTCollection, TTLibError

from core.packets import Packet, PacketStatus

SUPPORTED_EXTENSIONS = {
    ".ttf", ".otf", ".ttc", ".woff", ".woff2",
}

def _hash_file(path: Path) -> dict:
    algorithms = {
        "md5": hashlib.md5(),
        "sha1": hashlib.sha1(),
        "sha256": hashlib.sha256(),
    }

    with path.open("rb") as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b""):
            for algorithm in algorithms.values():
                algorithm.update(chunk)

    return {
        name: algorithm.hexdigest()
        for name, algorithm in algorithms.items()
    }

def _decode_name(record) -> str:
    try:
        return record.toUnicode().strip()
    except (UnicodeDecodeError, AttributeError):
        try:
            return record.string.decode(
                "utf-8",
                errors="replace",
            ).strip()
        except (AttributeError, UnicodeDecodeError):
            return ""

def _extract_names(font) -> dict:
    name_table = font.get("name")

    if name_table is None:
        return {}

    name_ids = {
        0: "copyright",
        1: "family",
        2: "subfamily",
        3: "unique_identifier",
        4: "full_name",
        5: "version",
        6: "postscript_name",
        7: "trademark",
        8: "manufacturer",
        9: "designer",
        10: "description",
        11: "vendor_url",
        12: "designer_url",
        13: "license",
        14: "license_url",
        16: "typographic_family",
        17: "typographic_subfamily",
        18: "compatible_full_name",
        19: "sample_text",
        20: "postscript_cid",
        21: "wws_family",
        22: "wws_subfamily",
    }

    names = {}

    for record in name_table.names:
        label = name_ids.get(record.nameID)

        if not label:
            continue

        value = _decode_name(record)

        if not value:
            continue

        names.setdefault(label, [])

        if value not in names[label]:
            names[label].append(value)

    return {
        key: values[0] if len(values) == 1 else values
        for key, values in names.items()
    }

def _extract_os2(font) -> dict:
    table = font.get("OS/2")

    if table is None:
        return {}

    return {
        "weight_class": getattr(table, "usWeightClass", None),
        "width_class": getattr(table, "usWidthClass", None),
        "embedding_permissions": getattr(
            table,
            "fsType",
            None,
        ),
        "vendor_id": getattr(table, "achVendID", None),
        "unicode_ranges": [
            index
            for index in range(128)
            if (
                getattr(table, f"ulUnicodeRange{index // 32 + 1}", 0)
                & (1 << (index % 32))
            )
        ],
    }

def _extract_metrics(font) -> dict:
    head = font.get("head")
    hhea = font.get("hhea")
    maxp = font.get("maxp")
    post = font.get("post")

    return {
        "units_per_em": getattr(head, "unitsPerEm", None),
        "font_revision": getattr(head, "fontRevision", None),
        "glyph_count": getattr(maxp, "numGlyphs", None),
        "ascender": getattr(hhea, "ascent", None),
        "descender": getattr(hhea, "descent", None),
        "line_gap": getattr(hhea, "lineGap", None),
        "italic_angle": getattr(post, "italicAngle", None),
        "underline_position": getattr(
            post,
            "underlinePosition",
            None,
        ),
        "underline_thickness": getattr(
            post,
            "underlineThickness",
            None,
        ),
        "is_fixed_pitch": bool(
            getattr(post, "isFixedPitch", 0)
        ),
    }

def _extract_character_coverage(font) -> dict:
    cmap = font.getBestCmap() or {}

    codepoints = sorted(cmap.keys())

    return {
        "character_count": len(codepoints),
        "codepoints": codepoints,
        "unicode_ranges": [
            {
                "start": f"U+{start:04X}",
                "end": f"U+{end:04X}",
            }
            for start, end in _group_codepoints(codepoints)
        ],
    }

def _group_codepoints(codepoints: list) -> list:
    if not codepoints:
        return []

    ranges = []
    start = previous = codepoints[0]

    for codepoint in codepoints[1:]:
        if codepoint == previous + 1:
            previous = codepoint
            continue

        ranges.append((start, previous))
        start = previous = codepoint

    ranges.append((start, previous))

    return ranges

def _extract_variable_axes(font) -> dict:
    if "fvar" not in font:
        return {
            "is_variable": False,
            "axes": [],
            "named_instances": [],
        }

    table = font["fvar"]

    axes = [
        {
            "tag": axis.axisTag,
            "name_id": axis.axisNameID,
            "minimum": axis.minValue,
            "default": axis.defaultValue,
            "maximum": axis.maxValue,
            "flags": axis.flags,
        }
        for axis in table.axes
    ]

    instances = [
        {
            "name_id": instance.subfamilyNameID,
            "postscript_name_id": instance.postscriptNameID,
            "coordinates": instance.coordinates,
        }
        for instance in table.instances
    ]

    return {
        "is_variable": True,
        "axes": axes,
        "named_instances": instances,
    }

def _extract_font(font, index: int = 0) -> dict:
    try:
        return {
            "index": index,
            "names": _extract_names(font),
            "metrics": _extract_metrics(font),
            "os2": _extract_os2(font),
            "character_coverage": _extract_character_coverage(font),
            "variable": _extract_variable_axes(font),
            "tables": sorted(font.keys()),
            "table_count": len(font.keys()),
        }
    finally:
        font.close()

def _extract_collection(path: Path) -> dict:
    collection = TTCollection(str(path), lazy=True)

    try:
        if len(collection.fonts) > 100:
            raise ValueError(
                "Font collection contains more than 100 fonts."
            )

        fonts = []

        for index, font in enumerate(collection.fonts):
            fonts.append(
                _extract_font(font, index)
            )

        return {
            "format": "TrueType Collection",
            "font_count": len(fonts),
            "fonts": fonts,
        }
    finally:
        collection.close()

def _extract_single_font(path: Path) -> dict:
    font = TTFont(
        str(path),
        lazy=True,
        recalcBBoxes=False,
        recalcTimestamp=False,
    )

    try:
        return {
            "format": font.sfntVersion,
            "font_count": 1,
            "fonts": [_extract_font(font)],
        }
    except Exception:
        font.close()
        raise

def fontextract(packet: Packet) -> Packet:
    result = packet.child(
        stage="extraction",
        artefact_type="font",
        status=PacketStatus.RUNNING,
    )

    try:
        path = Path(packet.input).expanduser()

        if not path.exists():
            raise FileNotFoundError(
                f"Font file not found: {path}"
            )

        if not path.is_file():
            raise ValueError("Input must be a file.")

        if path.suffix.lower() not in SUPPORTED_EXTENSIONS:
            raise ValueError(
                f"Unsupported font extension: {path.suffix}"
            )

        stat = path.stat()

        if path.suffix.lower() == ".ttc":
            font_data = _extract_collection(path)
        else:
            font_data = _extract_single_font(path)

        result.data = {
            "file": {
                "name": path.name,
                "extension": path.suffix.lower(),
                "absolute_path": str(path.resolve()),
                "size_bytes": stat.st_size,
                "modified": datetime.fromtimestamp(
                    stat.st_mtime,
                    tz=timezone.utc,
                ).isoformat(),
            },
            "hashes": _hash_file(path),
            "font": font_data,
        }

        result.status = PacketStatus.SUCCESS

    except FileNotFoundError as exc:
        result.add_error(
            code="FONT_FILE_NOT_FOUND",
            message=str(exc),
            component="extractors.font",
        )
        result.status = PacketStatus.FAILED

    except PermissionError as exc:
        result.add_error(
            code="FONT_ACCESS_DENIED",
            message=str(exc),
            component="extractors.font",
        )
        result.status = PacketStatus.FAILED

    except (TTLibError, OSError) as exc:
        result.add_error(
            code="INVALID_FONT_FILE",
            message=str(exc),
            component="extractors.font",
        )
        result.status = PacketStatus.FAILED

    except ValueError as exc:
        result.add_error(
            code="INVALID_FONT_INPUT",
            message=str(exc),
            component="extractors.font",
        )
        result.status = PacketStatus.FAILED

    except Exception as exc:
        result.add_error(
            code="FONT_EXTRACTION_FAILED",
            message=str(exc),
            component="extractors.font",
        )
        result.status = PacketStatus.FAILED

    return result