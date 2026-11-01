import csv
import hashlib
import io

from pathlib import Path
from collections import Counter

from core.packets import Packet, PacketStatus

def csvextract(packet: Packet) -> Packet:
    result = packet.child(
        stage="extraction",
        artefact_type="csv",
        status=PacketStatus.RUNNING,
    )

    try:
        source = packet.input

        if not isinstance(source, (str, Path)):
            raise ValueError("Input must be CSV text or a file path.")

        path = Path(source)
        source_type = "raw"
        source_path = None
        file_size = None

        if path.is_file():
            raw_bytes = path.read_bytes()

            try:
                raw = raw_bytes.decode("utf-8-sig")
            except UnicodeDecodeError as exc:
                raise ValueError(
                    "CSV file is not valid UTF-8."
                ) from exc

            source_type = "file"
            source_path = str(path.resolve())
            file_size = len(raw_bytes)
            source_hash = hashlib.sha256(raw_bytes).hexdigest()

        else:
            raw = str(source)

            if not raw.strip():
                raise ValueError("CSV input is empty.")

            source_hash = hashlib.sha256(
                raw.encode("utf-8")
            ).hexdigest()

        if not raw.strip():
            raise ValueError("CSV input is empty.")

        sample = raw[:8192]

        try:
            dialect = csv.Sniffer().sniff(sample)
        except csv.Error:
            dialect = csv.excel

        has_header = csv.Sniffer().has_header(sample)

        reader = csv.reader(
            io.StringIO(raw, newline=""),
            dialect,
        )

        records = list(reader)

        if not records:
            raise ValueError("CSV contains no records.")

        headers = records[0] if has_header else [
            f"column_{index + 1}"
            for index in range(len(records[0]))
        ]

        data_rows = records[1:] if has_header else records

        column_count = len(headers)

        rows = []
        row_lengths = Counter()
        duplicate_rows = Counter()
        empty_cells = 0

        column_values = {
            header: []
            for header in headers
        }

        for row_index, row in enumerate(data_rows, start=1):
            row_lengths[len(row)] += 1

            if len(row) < column_count:
                row = row + [None] * (
                    column_count - len(row)
                )

            row_data = {}

            for index, header in enumerate(headers):
                value = row[index] if index < len(row) else None

                if value is None or value == "":
                    empty_cells += 1

                column_values[header].append(value)

                row_data[header] = value

            rows.append({
                "row_number": row_index,
                "values": row_data,
                "raw_values": row,
            })

            duplicate_rows[tuple(row)] += 1

        column_statistics = {}

        for header, values in column_values.items():
            nonempty = [
                value for value in values
                if value is not None and value != ""
            ]

            types = Counter(
                _classify_value(value)
                for value in nonempty
            )

            column_statistics[header] = {
                "total_values": len(values),
                "nonempty_values": len(nonempty),
                "empty_values": len(values) - len(nonempty),
                "unique_values": len(set(nonempty)),
                "value_types": dict(types),
            }

        duplicates = [
            {
                "values": list(row),
                "occurrences": count,
            }
            for row, count in duplicate_rows.items()
            if count > 1
        ]

        result.data = {
            "source": {
                "type": source_type,
                "path": source_path,
                "size": file_size,
                "sha256": source_hash,
            },
            "csv": {
                "delimiter": dialect.delimiter,
                "quotechar": dialect.quotechar,
                "escapechar": dialect.escapechar,
                "has_header": has_header,
                "headers": headers,
                "column_count": column_count,
                "row_count": len(data_rows),
                "rows": rows,
                "statistics": {
                    "total_rows": len(data_rows),
                    "total_columns": column_count,
                    "total_cells": sum(
                        len(row) for row in records
                    ),
                    "empty_cells": empty_cells,
                    "duplicate_rows": len(duplicates),
                    "inconsistent_row_lengths": {
                        str(length): count
                        for length, count in row_lengths.items()
                        if length != column_count
                    },
                },
                "column_statistics": column_statistics,
                "duplicates": duplicates,
            },
        }

        result.status = PacketStatus.SUCCESS

    except FileNotFoundError:
        result.status = PacketStatus.FAILED
        result.add_error(
            code="CSV_FILE_NOT_FOUND",
            message="The specified CSV file could not be found.",
            component="extractors.csv",
        )

    except PermissionError:
        result.status = PacketStatus.FAILED
        result.add_error(
            code="CSV_PERMISSION_DENIED",
            message="Permission denied while reading the CSV file.",
            component="extractors.csv",
        )

    except csv.Error as exc:
        result.status = PacketStatus.FAILED
        result.add_error(
            code="CSV_PARSE_ERROR",
            message=str(exc),
            component="extractors.csv",
        )

    except (OSError, ValueError, TypeError) as exc:
        result.status = PacketStatus.FAILED
        result.add_error(
            code="CSV_EXTRACTION_FAILED",
            message=str(exc),
            component="extractors.csv",
        )

    except Exception as exc:
        result.status = PacketStatus.FAILED
        result.add_error(
            code="UNEXPECTED_ERROR",
            message=str(exc),
            component="extractors.csv",
        )

    return result

def _classify_value(value):
    if value is None or value == "":
        return "empty"

    try:
        int(value)
        return "integer"
    except ValueError:
        pass

    try:
        float(value)
        return "float"
    except ValueError:
        pass

    if value.lower() in ("true", "false"):
        return "boolean"

    return "string"