import configparser
import hashlib
import json
import re

from pathlib import Path

from core.packets import Packet, PacketStatus

MAX_FILE_SIZE = 10 * 1024 * 1024

def configextract(packet: Packet) -> Packet:
    result = packet.child(
        stage="extraction",
        artefact_type="config",
        status=PacketStatus.RUNNING,
    )

    try:
        source = packet.input

        if not isinstance(source, (str, Path)):
            raise ValueError("Input must be configuration text or a file path.")

        path = Path(source)
        source_type = "raw"
        source_path = None
        file_size = None
        extension = None

        if path.is_file():
            file_size = path.stat().st_size

            if file_size > MAX_FILE_SIZE:
                raise ValueError(
                    f"Configuration file exceeds the {MAX_FILE_SIZE}-byte limit."
                )

            raw_bytes = path.read_bytes()

            try:
                raw = raw_bytes.decode("utf-8-sig")
            except UnicodeDecodeError as exc:
                raise ValueError(
                    "Configuration file is not valid UTF-8."
                ) from exc

            source_type = "file"
            source_path = str(path.resolve())
            extension = path.suffix.lower()
            source_hash = hashlib.sha256(raw_bytes).hexdigest()

        else:
            raw = str(source)

            if not raw.strip():
                raise ValueError("Configuration input is empty.")

            if len(raw.encode("utf-8")) > MAX_FILE_SIZE:
                raise ValueError(
                    f"Configuration input exceeds the {MAX_FILE_SIZE}-byte limit."
                )

            source_hash = hashlib.sha256(
                raw.encode("utf-8")
            ).hexdigest()

        if not raw.strip():
            raise ValueError("Configuration input is empty.")

        config_format = _detect_format(raw, extension)

        if config_format == "ini":
            document = _parse_ini(raw)

        elif config_format == "toml":
            document = _parse_toml(raw)

        elif config_format == "yaml":
            document = _parse_yaml(raw)

        elif config_format == "json":
            document = _parse_json(raw)

        else:
            raise ValueError("Unsupported or unrecognised configuration format.")

        statistics = _inspect(document)

        result.data = {
            "source": {
                "type": source_type,
                "path": source_path,
                "format": config_format,
                "size": file_size,
                "sha256": source_hash,
            },
            "configuration": {
                "document": document,
                "statistics": statistics,
            },
        }

        result.status = PacketStatus.SUCCESS

    except FileNotFoundError:
        result.status = PacketStatus.FAILED
        result.add_error(
            code="CONFIG_FILE_NOT_FOUND",
            message="The specified configuration file could not be found.",
            component="extractors.config",
        )

    except PermissionError:
        result.status = PacketStatus.FAILED
        result.add_error(
            code="CONFIG_PERMISSION_DENIED",
            message="Permission denied while reading the configuration file.",
            component="extractors.config",
        )

    except Exception as exc:
        result.status = PacketStatus.FAILED
        result.add_error(
            code="CONFIG_EXTRACTION_FAILED",
            message=str(exc),
            component="extractors.config",
        )

    return result

def _detect_format(raw, extension=None):
    extensions = {
        ".ini": "ini",
        ".cfg": "ini",
        ".conf": "ini",
        ".toml": "toml",
        ".yaml": "yaml",
        ".yml": "yaml",
        ".json": "json",
    }

    if extension in extensions:
        return extensions[extension]

    candidate = raw.lstrip()

    if candidate.startswith(("{", "[")):
        try:
            json.loads(raw)
            return "json"
        except json.JSONDecodeError:
            pass

    if re.search(r"(?m)^\s*\[[^\]]+\]\s*$", raw):
        try:
            _parse_ini(raw)
            return "ini"
        except ValueError:
            pass

    if re.search(r"(?m)^\s*[^#\s][^:\n]*:\s+", raw):
        return "yaml"

    try:
        _parse_toml(raw)
        return "toml"
    except ValueError:
        pass

    raise ValueError("Unable to determine configuration format.")

def _parse_ini(raw):
    parser = configparser.ConfigParser(
        interpolation=None,
        strict=True,
    )

    try:
        parser.read_string(raw)
    except configparser.Error as exc:
        raise ValueError(f"Invalid INI configuration: {exc}") from exc

    document = {
        "defaults": dict(parser.defaults()),
        "sections": {},
    }

    for section in parser.sections():
        document["sections"][section] = dict(
            parser.items(section, raw=True)
        )

    return document

def _parse_toml(raw):
    try:
        import tomllib
    except ImportError as exc:
        raise ValueError(
            "TOML parsing requires Python 3.11 or newer."
        ) from exc

    try:
        return tomllib.loads(raw)
    except tomllib.TOMLDecodeError as exc:
        raise ValueError(f"Invalid TOML configuration: {exc}") from exc

def _parse_yaml(raw):
    try:
        import yaml
    except ImportError as exc:
        raise ValueError(
            "YAML parsing requires PyYAML. Install it using: pip install PyYAML"
        ) from exc

    try:
        document = yaml.safe_load(raw)
    except yaml.YAMLError as exc:
        raise ValueError(f"Invalid YAML configuration: {exc}") from exc

    return document

def _parse_json(raw):
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid JSON configuration: {exc}") from exc

def _inspect(document):
    statistics = {
        "objects": 0,
        "arrays": 0,
        "keys": 0,
        "values": 0,
        "strings": 0,
        "integers": 0,
        "floats": 0,
        "booleans": 0,
        "nulls": 0,
        "max_depth": 0,
    }

    def inspect(value, depth=0):
        statistics["max_depth"] = max(
            statistics["max_depth"],
            depth,
        )

        if isinstance(value, dict):
            statistics["objects"] += 1

            for item in value.values():
                statistics["keys"] += 1
                inspect(item, depth + 1)

        elif isinstance(value, list):
            statistics["arrays"] += 1

            for item in value:
                inspect(item, depth + 1)

        elif isinstance(value, bool):
            statistics["booleans"] += 1
            statistics["values"] += 1

        elif isinstance(value, int):
            statistics["integers"] += 1
            statistics["values"] += 1

        elif isinstance(value, float):
            statistics["floats"] += 1
            statistics["values"] += 1

        elif isinstance(value, str):
            statistics["strings"] += 1
            statistics["values"] += 1

        elif value is None:
            statistics["nulls"] += 1
            statistics["values"] += 1

    inspect(document)

    return statistics