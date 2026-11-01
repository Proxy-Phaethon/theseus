import hashlib
import json
from pathlib import Path
from collections import Counter
from datetime import datetime, timezone

from core.packets import PacketStatus

def jsonextract(packet):
    result = packet.child(
        stage="extraction",
        artefact_type="json",
        status=PacketStatus.RUNNING,
    )

    try:
        source = packet.input

        if not isinstance(source, (str, Path)):
            raise ValueError("Input must be a JSON string or file path.")

        path = Path(source) if isinstance(source, (str, Path)) else None

        if path is not None and path.is_file():
            raw = path.read_text(encoding="utf-8-sig")
            source_type = "file"
            source_path = str(path.resolve())
            file_size = path.stat().st_size
            file_hash = _hash_file(path)
        else:
            raw = str(source)
            source_type = "raw"
            source_path = None
            file_size = None
            file_hash = hashlib.sha256(raw.encode("utf-8")).hexdigest()

        if not raw.strip():
            raise ValueError("JSON input is empty.")

        duplicate_keys = []

        def object_pairs(pairs):
            obj = {}

            for key, value in pairs:
                if key in obj:
                    duplicate_keys.append(key)

                obj[key] = value

            return obj

        document = json.loads(
            raw,
            object_pairs_hook=object_pairs,
        )

        statistics = {
            "objects": 0,
            "arrays": 0,
            "strings": 0,
            "numbers": 0,
            "integers": 0,
            "floats": 0,
            "booleans": 0,
            "nulls": 0,
            "keys": 0,
        }

        keys = Counter()
        value_types = Counter()
        max_depth = 0

        def inspect(value, depth=0):
            nonlocal max_depth

            max_depth = max(max_depth, depth)

            if isinstance(value, dict):
                statistics["objects"] += 1

                for key, item in value.items():
                    statistics["keys"] += 1
                    keys[key] += 1
                    inspect(item, depth + 1)

            elif isinstance(value, list):
                statistics["arrays"] += 1

                for item in value:
                    inspect(item, depth + 1)

            elif isinstance(value, bool):
                statistics["booleans"] += 1
                value_types["boolean"] += 1

            elif isinstance(value, int):
                statistics["numbers"] += 1
                statistics["integers"] += 1
                value_types["integer"] += 1

            elif isinstance(value, float):
                statistics["numbers"] += 1
                statistics["floats"] += 1
                value_types["float"] += 1

            elif isinstance(value, str):
                statistics["strings"] += 1
                value_types["string"] += 1

            elif value is None:
                statistics["nulls"] += 1
                value_types["null"] += 1

        inspect(document)

        root_type = (
            "object" if isinstance(document, dict)
            else "array" if isinstance(document, list)
            else "null" if document is None
            else "boolean" if isinstance(document, bool)
            else "integer" if isinstance(document, int)
            else "float" if isinstance(document, float)
            else "string"
        )

        result.data = {
            "source": {
                "type": source_type,
                "path": source_path,
                "size": file_size,
                "sha256": file_hash,
            },
            "json": {
                "root_type": root_type,
                "document": document,
                "statistics": statistics,
                "max_depth": max_depth,
                "unique_keys": len(keys),
                "key_occurrences": dict(keys),
                "value_types": dict(value_types),
                "duplicate_keys": sorted(set(duplicate_keys)),
                "has_duplicate_keys": bool(duplicate_keys),
            },
        }

        result.status = PacketStatus.SUCCESS

    except FileNotFoundError:
        result.status = PacketStatus.FAILED
        result.add_error(
            code="JSON_FILE_NOT_FOUND",
            message="The specified JSON file could not be found.",
            component="extractors.json",
        )

    except PermissionError:
        result.status = PacketStatus.FAILED
        result.add_error(
            code="JSON_PERMISSION_DENIED",
            message="Permission denied while reading the JSON file.",
            component="extractors.json",
        )

    except json.JSONDecodeError as exc:
        result.status = PacketStatus.FAILED
        result.add_error(
            code="INVALID_JSON",
            message=f"Invalid JSON at line {exc.lineno}, column {exc.colno}: {exc.msg}",
            component="extractors.json",
        )

    except (OSError, ValueError, TypeError) as exc:
        result.status = PacketStatus.FAILED
        result.add_error(
            code="JSON_EXTRACTION_FAILED",
            message=str(exc),
            component="extractors.json",
        )

    except Exception as exc:
        result.status = PacketStatus.FAILED
        result.add_error(
            code="UNEXPECTED_ERROR",
            message=str(exc),
            component="extractors.json",
        )

    return result

def _hash_file(path):
    digest = hashlib.sha256()

    with path.open("rb") as file:
        for chunk in iter(lambda: file.read(65536), b""):
            digest.update(chunk)

    return digest.hexdigest()