import base64
import hashlib
import re
import struct

from pathlib import Path

from core.packets import Packet, PacketStatus

MAX_FILE_SIZE = 256 * 1024 * 1024
MAX_KEYS = 10000
MAX_DEPTH = 64

def _decode_reg(raw_bytes):
    if raw_bytes.startswith(b"\xff\xfe"):
        return raw_bytes.decode("utf-16")

    if raw_bytes.startswith(b"\xfe\xff"):
        return raw_bytes.decode("utf-16")

    return raw_bytes.decode("utf-8-sig")

def registryextract(packet: Packet) -> Packet:
    result = packet.child(
        stage="extraction",
        artefact_type="registry",
        status=PacketStatus.RUNNING,
    )

    try:
        source = packet.input

        if not isinstance(source, (str, Path)):
            raise ValueError("Input must be a Registry file path or .reg text.")

        path = Path(source)
        source_type = None

        if path.is_file():
            size = path.stat().st_size

            if size > MAX_FILE_SIZE:
                raise ValueError(
                    f"Registry file exceeds the {MAX_FILE_SIZE}-byte limit."
                )

            raw_bytes = path.read_bytes()
            source_hash = hashlib.sha256(raw_bytes).hexdigest()

            source_type = _identify_file(raw_bytes, path)

            if source_type == "hive":
                document = _parse_hive(path)

            elif source_type == "reg":
                raw = _decode_reg(raw_bytes)
                document = _parse_reg(raw)

            else:
                raise ValueError("Unrecognised Registry file format.")

            source_metadata = {
                "type": "file",
                "format": source_type,
                "path": str(path.resolve()),
                "name": path.name,
                "size": size,
                "sha256": source_hash,
            }

        else:
            raw = str(source)

            if not raw.strip():
                raise ValueError("Registry input is empty.")

            if len(raw.encode("utf-8")) > MAX_FILE_SIZE:
                raise ValueError(
                    f"Registry input exceeds the {MAX_FILE_SIZE}-byte limit."
                )

            if not _looks_like_reg(raw):
                raise ValueError(
                    "Raw input must be a valid-looking Windows .reg export."
                )

            source_type = "reg"
            document = _parse_reg(raw)

            source_metadata = {
                "type": "raw",
                "format": "reg",
                "path": None,
                "name": None,
                "size": len(raw.encode("utf-8")),
                "sha256": hashlib.sha256(
                    raw.encode("utf-8")
                ).hexdigest(),
            }

        result.data = {
            "source": source_metadata,
            "registry": document,
        }

        result.status = (
            PacketStatus.PARTIAL_SUCCESS
            if document.get("invalid_lines")
            else PacketStatus.SUCCESS
        )

        if document.get("invalid_lines"):
            result.add_error(
                code="REGISTRY_PARSE_WARNINGS",
                message=(
                    f"{len(document['invalid_lines'])} Registry entries "
                    "could not be parsed."
                ),
                component="extractors.registry",
            )

    except FileNotFoundError:
        result.status = PacketStatus.FAILED
        result.add_error(
            code="REGISTRY_FILE_NOT_FOUND",
            message="The specified Registry file could not be found.",
            component="extractors.registry",
        )

    except PermissionError:
        result.status = PacketStatus.FAILED
        result.add_error(
            code="REGISTRY_PERMISSION_DENIED",
            message="Permission denied while reading the Registry file.",
            component="extractors.registry",
        )

    except Exception as exc:
        result.status = PacketStatus.FAILED
        result.add_error(
            code="REGISTRY_EXTRACTION_FAILED",
            message=str(exc),
            component="extractors.registry",
        )

    return result

def _identify_file(raw_bytes, path):
    if raw_bytes.startswith(b"regf"):
        return "hive"

    if path.suffix.lower() == ".reg":
        return "reg"

    try:
        text = raw_bytes.decode("utf-8-sig")
    except UnicodeDecodeError:
        return None

    if _looks_like_reg(text):
        return "reg"

    return None

def _looks_like_reg(raw):
    return bool(
        re.search(
            r"(?im)^\s*Windows Registry Editor Version 5\.00\s*$"
            r"|^\s*REGEDIT4\s*$",
            raw,
        )
    )

def _parse_hive(path):
    try:
        from Registry import Registry as RegistryParser
    except ImportError as exc:
        raise ValueError(
            "Hive parsing requires python-registry. "
            "Install it using: pip install python-registry"
        ) from exc

    hive = RegistryParser(str(path))

    statistics = {
        "keys": 0,
        "values": 0,
        "max_depth": 0,
        "truncated": False,
    }

    def inspect_key(key, depth=0):
        if statistics["keys"] >= MAX_KEYS:
            statistics["truncated"] = True
            return None

        if depth > MAX_DEPTH:
            statistics["truncated"] = True
            return None

        statistics["keys"] += 1
        statistics["max_depth"] = max(
            statistics["max_depth"],
            depth,
        )

        try:
            timestamp = key.timestamp()
            timestamp = (
                timestamp.isoformat()
                if timestamp is not None
                else None
            )
        except Exception:
            timestamp = None

        extracted_values = []

        for value in key.values():
            statistics["values"] += 1

            try:
                raw_value = value.value()
                value_data = _normalise_hive_value(raw_value)
            except Exception as exc:
                value_data = {
                    "error": str(exc),
                }

            extracted_values.append({
                "name": value.name(),
                "type": value.value_type_str(),
                "data": value_data,
            })

        extracted_subkeys = []

        for subkey in key.subkeys():
            if statistics["keys"] >= MAX_KEYS:
                statistics["truncated"] = True
                break

            child = inspect_key(subkey, depth + 1)

            if child is not None:
                extracted_subkeys.append(child)

        return {
            "name": key.name(),
            "path": key.path(),
            "last_written": timestamp,
            "values": extracted_values,
            "subkeys": extracted_subkeys,
        }

    root = inspect_key(hive.root())

    return {
        "format": "hive",
        "root": root,
        "statistics": statistics,
        "invalid_lines": [],
    }

def _normalise_hive_value(value):
    if isinstance(value, bytes):
        return {
            "encoding": "base64",
            "data": base64.b64encode(value).decode("ascii"),
            "size": len(value),
        }

    if isinstance(value, (str, int, float, bool)) or value is None:
        return value

    if isinstance(value, (list, tuple)):
        return [
            _normalise_hive_value(item)
            for item in value
        ]

    if hasattr(value, "isoformat"):
        return value.isoformat()

    return str(value)

def _parse_reg(raw):
    lines = _join_continuations(raw.splitlines())

    document = {
        "format": "reg",
        "version": None,
        "keys": [],
        "deleted_keys": [],
        "invalid_lines": [],
        "statistics": {
            "keys": 0,
            "values": 0,
            "deleted_keys": 0,
            "deleted_values": 0,
        },
    }

    current_key = None

    for line_number, line in lines:
        stripped = line.strip()

        if not stripped or stripped.startswith(";"):
            continue

        if stripped.startswith("Windows Registry Editor Version"):
            document["version"] = stripped
            continue

        if stripped.upper() == "REGEDIT4":
            document["version"] = stripped
            continue

        if stripped.startswith("[") and stripped.endswith("]"):
            key_path = stripped[1:-1]
            deleted = key_path.startswith("-")

            if deleted:
                document["deleted_keys"].append(
                    key_path[1:]
                )
                document["statistics"]["deleted_keys"] += 1
                current_key = None
                continue

            current_key = {
                "path": key_path,
                "values": [],
            }

            document["keys"].append(current_key)
            document["statistics"]["keys"] += 1
            continue

        if current_key is None:
            document["invalid_lines"].append({
                "line": line_number,
                "content": line,
                "reason": "Value declaration appears outside a Registry key.",
            })
            continue

        try:
            parsed = _parse_reg_value(stripped)

            if parsed.get("deleted"):
                document["statistics"]["deleted_values"] += 1
            else:
                document["statistics"]["values"] += 1

            current_key["values"].append(parsed)

        except ValueError as exc:
            document["invalid_lines"].append({
                "line": line_number,
                "content": line,
                "reason": str(exc),
            })

    return document

def _join_continuations(lines):
    result = []
    buffer = ""
    start_line = 1

    for line_number, line in enumerate(lines, start=1):
        if not buffer:
            start_line = line_number

        current = line.rstrip()

        if current.endswith("\\"):
            buffer += current[:-1]
            continue

        buffer += current
        result.append((start_line, buffer))
        buffer = ""

    if buffer:
        result.append((start_line, buffer))

    return result

def _parse_reg_value(line):
    if "=" not in line:
        raise ValueError("Missing assignment operator.")

    name_part, data_part = line.split("=", 1)
    name_part = name_part.strip()
    data_part = data_part.strip()

    if name_part == "@":
        name = None
    elif name_part.startswith('"') and name_part.endswith('"'):
        name = _unescape_reg_string(name_part[1:-1])
    else:
        raise ValueError("Invalid Registry value name.")

    if data_part == "-":
        return {
            "name": name,
            "deleted": True,
            "type": None,
            "data": None,
        }

    if data_part.startswith('"') and data_part.endswith('"'):
        return {
            "name": name,
            "deleted": False,
            "type": "REG_SZ",
            "data": _unescape_reg_string(data_part[1:-1]),
        }

    if data_part.lower().startswith("dword:"):
        raw_value = data_part[6:]

        if not re.fullmatch(r"[0-9a-fA-F]{8}", raw_value):
            raise ValueError("Invalid DWORD value.")

        return {
            "name": name,
            "deleted": False,
            "type": "REG_DWORD",
            "data": int(raw_value, 16),
        }

    if data_part.lower().startswith("qword:"):
        raw_value = data_part[6:]

        if not re.fullmatch(r"[0-9a-fA-F]{16}", raw_value):
            raise ValueError("Invalid QWORD value.")

        return {
            "name": name,
            "deleted": False,
            "type": "REG_QWORD",
            "data": int(raw_value, 16),
        }

    if data_part.lower().startswith("hex"):
        return _parse_reg_hex(name, data_part)

    raise ValueError("Unsupported Registry value representation.")

def _parse_reg_hex(name, data_part):
    match = re.match(
        r"^hex(?:\(([0-9a-fA-F]+)\))?:(.*)$",
        data_part,
        re.IGNORECASE,
    )

    if not match:
        raise ValueError("Invalid hexadecimal Registry value.")

    type_code = match.group(1)
    hex_data = match.group(2).replace(",", "").replace(" ", "")

    if len(hex_data) % 2 or not re.fullmatch(
        r"[0-9a-fA-F]*",
        hex_data,
    ):
        raise ValueError("Invalid hexadecimal data.")

    raw_bytes = bytes.fromhex(hex_data)

    type_codes = {
        None: "REG_BINARY",
        "0": "REG_NONE",
        "1": "REG_SZ",
        "2": "REG_EXPAND_SZ",
        "3": "REG_BINARY",
        "4": "REG_DWORD",
        "5": "REG_DWORD_BIG_ENDIAN",
        "6": "REG_LINK",
        "7": "REG_MULTI_SZ",
        "b": "REG_QWORD",
    }

    registry_type = type_codes.get(
        type_code.lower() if type_code else None,
        f"REG_UNKNOWN_{type_code}",
    )

    if registry_type in ("REG_SZ", "REG_EXPAND_SZ", "REG_LINK"):
        try:
            data = raw_bytes.decode("utf-16le").rstrip("\x00")
        except UnicodeDecodeError:
            data = _binary_value(raw_bytes)

    elif registry_type == "REG_MULTI_SZ":
        try:
            data = [
                item
                for item in raw_bytes.decode("utf-16le").split("\x00")
                if item
            ]
        except UnicodeDecodeError:
            data = _binary_value(raw_bytes)

    elif registry_type == "REG_DWORD" and len(raw_bytes) == 4:
        data = struct.unpack("<I", raw_bytes)[0]

    elif registry_type == "REG_DWORD_BIG_ENDIAN" and len(raw_bytes) == 4:
        data = struct.unpack(">I", raw_bytes)[0]

    elif registry_type == "REG_QWORD" and len(raw_bytes) == 8:
        data = struct.unpack("<Q", raw_bytes)[0]

    else:
        data = _binary_value(raw_bytes)

    return {
        "name": name,
        "deleted": False,
        "type": registry_type,
        "data": data,
    }

def _binary_value(raw_bytes):
    return {
        "encoding": "base64",
        "data": base64.b64encode(raw_bytes).decode("ascii"),
        "size": len(raw_bytes),
    }

def _unescape_reg_string(value):
    return (
        value
        .replace(r"\\", "\\")
        .replace(r"\"", '"')
    )