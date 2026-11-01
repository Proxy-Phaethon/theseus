import base64
import hashlib
import sqlite3

from pathlib import Path

from core.packets import Packet, PacketStatus

MAX_ROWS_PER_TABLE = 1000
MAX_TABLES = 1000

def sqliteextract(packet: Packet) -> Packet:
    result = packet.child(
        stage="extraction",
        artefact_type="sqlite",
        status=PacketStatus.RUNNING,
    )

    connection = None

    try:
        source = packet.input

        if not isinstance(source, (str, Path)):
            raise ValueError("Input must be a SQLite database file path.")

        path = Path(source).expanduser()

        if not path.exists():
            raise FileNotFoundError("SQLite database file not found.")

        if not path.is_file():
            raise ValueError("Input must be a regular file.")

        if path.suffix.lower() not in (".db", ".sqlite", ".sqlite3"):
            raise ValueError("Unsupported SQLite file extension.")

        with path.open("rb") as file:
            header = file.read(16)

        if header != b"SQLite format 3\x00":
            raise ValueError("File does not have a valid SQLite header.")

        source_hash = _hash_file(path)

        database_uri = path.resolve().as_uri() + "?mode=ro"

        connection = sqlite3.connect(
            database_uri,
            uri=True,
            timeout=5,
        )

        connection.row_factory = sqlite3.Row

        connection.execute("PRAGMA query_only = ON")

        integrity = connection.execute(
            "PRAGMA integrity_check"
        ).fetchall()

        integrity_results = [
            row[0] for row in integrity
        ]

        schema_version = connection.execute(
            "PRAGMA schema_version"
        ).fetchone()[0]

        user_version = connection.execute(
            "PRAGMA user_version"
        ).fetchone()[0]

        encoding = connection.execute(
            "PRAGMA encoding"
        ).fetchone()[0]

        schema_objects = connection.execute("""
            SELECT
                type,
                name,
                tbl_name,
                sql
            FROM sqlite_master
            WHERE name NOT LIKE 'sqlite_%'
            ORDER BY type, name
        """).fetchall()

        tables = [
            row for row in schema_objects
            if row["type"] == "table"
        ]

        views = [
            row for row in schema_objects
            if row["type"] == "view"
        ]

        indexes = [
            row for row in schema_objects
            if row["type"] == "index"
        ]

        triggers = [
            row for row in schema_objects
            if row["type"] == "trigger"
        ]

        if len(tables) > MAX_TABLES:
            raise ValueError(
                f"Database contains more than {MAX_TABLES} tables."
            )

        extracted_tables = []

        total_rows = 0
        total_columns = 0

        for table in tables:
            table_name = table["name"]

            quoted_name = _quote_identifier(table_name)

            columns = connection.execute(
                f"PRAGMA table_info({quoted_name})"
            ).fetchall()

            foreign_keys = connection.execute(
                f"PRAGMA foreign_key_list({quoted_name})"
            ).fetchall()

            count = connection.execute(
                f"SELECT COUNT(*) FROM {quoted_name}"
            ).fetchone()[0]

            total_rows += count
            total_columns += len(columns)

            records = connection.execute(
                f"SELECT * FROM {quoted_name} LIMIT ?",
                (MAX_ROWS_PER_TABLE,),
            ).fetchall()

            extracted_tables.append({
                "name": table_name,
                "schema": table["sql"],
                "row_count": count,
                "columns": [
                    {
                        "cid": column["cid"],
                        "name": column["name"],
                        "type": column["type"],
                        "not_null": bool(column["notnull"]),
                        "default_value": column["dflt_value"],
                        "primary_key_position": column["pk"],
                    }
                    for column in columns
                ],
                "foreign_keys": [
                    dict(foreign_key)
                    for foreign_key in foreign_keys
                ],
                "records": [
                    {
                        key: _normalise_value(row[key])
                        for key in row.keys()
                    }
                    for row in records
                ],
                "records_extracted": len(records),
                "records_truncated": count > MAX_ROWS_PER_TABLE,
            })

        result.data = {
            "source": {
                "path": str(path.resolve()),
                "name": path.name,
                "size": path.stat().st_size,
                "sha256": source_hash,
            },
            "database": {
                "engine": "SQLite",
                "encoding": encoding,
                "schema_version": schema_version,
                "user_version": user_version,
                "integrity_check": integrity_results,
                "is_valid": integrity_results == ["ok"],
            },
            "statistics": {
                "tables": len(tables),
                "views": len(views),
                "indexes": len(indexes),
                "triggers": len(triggers),
                "total_columns": total_columns,
                "total_rows": total_rows,
                "rows_extracted": sum(
                    table["records_extracted"]
                    for table in extracted_tables
                ),
            },
            "tables": extracted_tables,
            "views": [
                {
                    "name": view["name"],
                    "table": view["tbl_name"],
                    "definition": view["sql"],
                }
                for view in views
            ],
            "indexes": [
                {
                    "name": index["name"],
                    "table": index["tbl_name"],
                    "definition": index["sql"],
                }
                for index in indexes
            ],
            "triggers": [
                {
                    "name": trigger["name"],
                    "table": trigger["tbl_name"],
                    "definition": trigger["sql"],
                }
                for trigger in triggers
            ],
        }

        result.status = (
            PacketStatus.SUCCESS
            if integrity_results == ["ok"]
            else PacketStatus.PARTIAL_SUCCESS
        )

        if integrity_results != ["ok"]:
            result.add_error(
                code="SQLITE_INTEGRITY_WARNING",
                message="SQLite integrity check reported problems: "
                + "; ".join(integrity_results),
                component="extractors.sqlite",
            )

    except FileNotFoundError:
        result.status = PacketStatus.FAILED
        result.add_error(
            code="SQLITE_FILE_NOT_FOUND",
            message="The specified database file could not be found.",
            component="extractors.sqlite",
        )

    except PermissionError:
        result.status = PacketStatus.FAILED
        result.add_error(
            code="SQLITE_PERMISSION_DENIED",
            message="Permission denied while accessing the database.",
            component="extractors.sqlite",
        )

    except sqlite3.DatabaseError as exc:
        result.status = PacketStatus.FAILED
        result.add_error(
            code="SQLITE_DATABASE_ERROR",
            message=str(exc),
            component="extractors.sqlite",
        )

    except (OSError, ValueError, TypeError) as exc:
        result.status = PacketStatus.FAILED
        result.add_error(
            code="SQLITE_EXTRACTION_FAILED",
            message=str(exc),
            component="extractors.sqlite",
        )

    except Exception as exc:
        result.status = PacketStatus.FAILED
        result.add_error(
            code="UNEXPECTED_ERROR",
            message=str(exc),
            component="extractors.sqlite",
        )

    finally:
        if connection is not None:
            connection.close()

    return result

def _quote_identifier(identifier):
    return '"' + identifier.replace('"', '""') + '"'

def _normalise_value(value):
    if isinstance(value, bytes):
        return {
            "encoding": "base64",
            "value": base64.b64encode(value).decode("ascii"),
            "size": len(value),
        }

    return value

def _hash_file(path):
    digest = hashlib.sha256()

    with path.open("rb") as file:
        for chunk in iter(lambda: file.read(65536), b""):
            digest.update(chunk)

    return digest.hexdigest()