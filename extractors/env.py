import hashlib
import re

from pathlib import Path

from core.packets import Packet, PacketStatus

MAX_FILE_SIZE = 5 * 1024 * 1024

def envextract(packet: Packet) -> Packet:
    result = packet.child(
        stage="extraction",
        artefact_type="env",
        status=PacketStatus.RUNNING,
    )

    try:
        source = packet.input

        if not isinstance(source, (str, Path)):
            raise ValueError("Input must be environment text or a file path.")

        path = Path(source)
        source_type = "raw"
        source_path = None
        file_size = None

        if path.is_file():
            file_size = path.stat().st_size

            if file_size > MAX_FILE_SIZE:
                raise ValueError(
                    f"Environment file exceeds the {MAX_FILE_SIZE}-byte limit."
                )

            raw_bytes = path.read_bytes()

            try:
                raw = raw_bytes.decode("utf-8-sig")
            except UnicodeDecodeError as exc:
                raise ValueError(
                    "Environment file is not valid UTF-8."
                ) from exc

            source_type = "file"
            source_path = str(path.resolve())
            source_hash = hashlib.sha256(raw_bytes).hexdigest()

        else:
            raw = str(source)

            if not raw.strip():
                raise ValueError("Environment input is empty.")

            if len(raw.encode("utf-8")) > MAX_FILE_SIZE:
                raise ValueError(
                    f"Environment input exceeds the {MAX_FILE_SIZE}-byte limit."
                )

            source_hash = hashlib.sha256(
                raw.encode("utf-8")
            ).hexdigest()

        if not raw.strip():
            raise ValueError("Environment input is empty.")

        variables = []
        comments = []
        invalid_lines = []
        duplicate_names = {}

        values = {}
        line_count = 0

        for line_number, original_line in enumerate(
            raw.splitlines(),
            start=1,
        ):
            line_count += 1
            stripped = original_line.strip()

            if not stripped:
                continue

            if stripped.startswith("#"):
                comments.append({
                    "line": line_number,
                    "text": stripped[1:].strip(),
                })
                continue

            export = False
            candidate = stripped

            if candidate.startswith("export "):
                export = True
                candidate = candidate[7:].lstrip()

            if "=" not in candidate:
                invalid_lines.append({
                    "line": line_number,
                    "content": original_line,
                    "reason": "Missing assignment operator.",
                })
                continue

            name, value = candidate.split("=", 1)
            name = name.strip()
            value = value.strip()

            if not re.fullmatch(
                r"[A-Za-z_][A-Za-z0-9_]*",
                name,
            ):
                invalid_lines.append({
                    "line": line_number,
                    "content": original_line,
                    "reason": "Invalid environment variable name.",
                })
                continue

            parsed_value, quote_type, inline_comment = _parse_value(value)

            variable = {
                "name": name,
                "value": parsed_value,
                "line": line_number,
                "export": export,
                "quote_type": quote_type,
                "inline_comment": inline_comment,
                "is_empty": parsed_value == "",
                "is_variable_reference": bool(
                    re.search(
                        r"\$(?:\{[A-Za-z_][A-Za-z0-9_]*\}|[A-Za-z_][A-Za-z0-9_]*)",
                        parsed_value,
                    )
                ),
            }

            variables.append(variable)

            if name in values:
                duplicate_names.setdefault(name, []).append({
                    "line": line_number,
                    "value": parsed_value,
                })

            values[name] = parsed_value

        result.data = {
            "source": {
                "type": source_type,
                "path": source_path,
                "size": file_size,
                "sha256": source_hash,
            },
            "environment": {
                "variables": variables,
                "resolved_values": values,
                "comments": comments,
                "invalid_lines": invalid_lines,
                "duplicates": duplicate_names,
                "statistics": {
                    "total_lines": line_count,
                    "variable_count": len(variables),
                    "unique_variable_count": len(values),
                    "comment_count": len(comments),
                    "invalid_line_count": len(invalid_lines),
                    "duplicate_variable_count": len(duplicate_names),
                    "empty_value_count": sum(
                        variable["is_empty"]
                        for variable in variables
                    ),
                    "export_count": sum(
                        variable["export"]
                        for variable in variables
                    ),
                    "variable_reference_count": sum(
                        variable["is_variable_reference"]
                        for variable in variables
                    ),
                },
            },
        }

        result.status = (
            PacketStatus.PARTIAL_SUCCESS
            if invalid_lines
            else PacketStatus.SUCCESS
        )

        if invalid_lines:
            result.add_error(
                code="ENV_INVALID_LINES",
                message=f"{len(invalid_lines)} lines could not be parsed.",
                component="extractors.env",
            )

    except FileNotFoundError:
        result.status = PacketStatus.FAILED
        result.add_error(
            code="ENV_FILE_NOT_FOUND",
            message="The specified environment file could not be found.",
            component="extractors.env",
        )

    except PermissionError:
        result.status = PacketStatus.FAILED
        result.add_error(
            code="ENV_PERMISSION_DENIED",
            message="Permission denied while reading the environment file.",
            component="extractors.env",
        )

    except (OSError, ValueError, TypeError) as exc:
        result.status = PacketStatus.FAILED
        result.add_error(
            code="ENV_EXTRACTION_FAILED",
            message=str(exc),
            component="extractors.env",
        )

    except Exception as exc:
        result.status = PacketStatus.FAILED
        result.add_error(
            code="UNEXPECTED_ERROR",
            message=str(exc),
            component="extractors.env",
        )

    return result

def _parse_value(value):
    quote_type = None
    inline_comment = None

    if value.startswith(("'", '"')):
        quote = value[0]
        quote_type = "single" if quote == "'" else "double"

        closing = value.find(quote, 1)

        if closing == -1:
            return value[1:], quote_type, None

        parsed = value[1:closing]
        remainder = value[closing + 1:].strip()

        if remainder.startswith("#"):
            inline_comment = remainder[1:].strip()

        return parsed, quote_type, inline_comment

    comment_index = value.find(" #")

    if comment_index != -1:
        inline_comment = value[comment_index + 2:].strip()
        value = value[:comment_index].rstrip()

    return value, quote_type, inline_comment