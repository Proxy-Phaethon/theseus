import hashlib
import json
import sqlite3

from pathlib import Path
from datetime import datetime, timezone

from core.packets import Packet, PacketStatus

MAX_FILE_SIZE = 256 * 1024 * 1024
MAX_RECORDS = 10000

SUPPORTED_DATABASES = {
    "history": "history",
    "places.sqlite": "firefox",
    "cookies": "cookies",
    "cookies.sqlite": "firefox",
    "login data": "logins",
    "web data": "web_data",
}

def browserextract(packet: Packet) -> Packet:
    result = packet.child(
        stage="extraction",
        artefact_type="browser",
        status=PacketStatus.RUNNING,
    )

    try:
        source = packet.input

        if not isinstance(source, (str, Path)):
            raise ValueError("Input must be a browser artefact file or profile directory.")

        path = Path(source).expanduser()

        if not path.exists():
            raise FileNotFoundError("Browser artefact does not exist.")

        if path.is_symlink():
            raise ValueError("Symbolic links are not supported.")

        if path.is_dir():
            result.data = _extract_profile(path)
        elif path.is_file():
            result.data = _extract_file(path)
        else:
            raise ValueError("Input must be a regular file or browser profile directory.")

        result.status = PacketStatus.SUCCESS

    except FileNotFoundError as exc:
        result.status = PacketStatus.FAILED
        result.add_error(
            code="BROWSER_FILE_NOT_FOUND",
            message=str(exc),
            component="extractors.browser",
        )

    except PermissionError:
        result.status = PacketStatus.FAILED
        result.add_error(
            code="BROWSER_PERMISSION_DENIED",
            message="Permission denied while reading browser artefacts.",
            component="extractors.browser",
        )

    except (OSError, ValueError, sqlite3.Error, json.JSONDecodeError) as exc:
        result.status = PacketStatus.FAILED
        result.add_error(
            code="BROWSER_EXTRACTION_FAILED",
            message=str(exc),
            component="extractors.browser",
        )

    except Exception as exc:
        result.status = PacketStatus.FAILED
        result.add_error(
            code="UNEXPECTED_ERROR",
            message=str(exc),
            component="extractors.browser",
        )

    return result

def _extract_profile(profile):
    profiles = []

    candidates = [
        profile,
        *[
            item for item in profile.iterdir()
            if item.is_dir() and not item.is_symlink()
        ],
    ]

    for candidate in candidates:
        artefacts = {}

        for filename in (
            "History",
            "places.sqlite",
            "Cookies",
            "cookies.sqlite",
            "Login Data",
            "Web Data",
            "Bookmarks",
        ):
            path = candidate / filename

            if not path.is_file() or path.is_symlink():
                continue

            try:
                artefacts[filename] = _extract_file(path)
            except (OSError, ValueError, sqlite3.Error, json.JSONDecodeError) as exc:
                artefacts[filename] = {
                    "status": "failed",
                    "error": str(exc),
                }

        if artefacts:
            profiles.append({
                "profile": str(candidate),
                "artefacts": artefacts,
            })

    return {
        "input_type": "profile_directory",
        "profile_count": len(profiles),
        "profiles": profiles,
    }

def _extract_file(path):
    size = path.stat().st_size

    if size > MAX_FILE_SIZE:
        raise ValueError(
            f"Browser artefact exceeds the {MAX_FILE_SIZE}-byte limit."
        )

    raw = path.read_bytes()

    metadata = {
        "filename": path.name,
        "path": str(path.resolve()),
        "size": size,
        "sha256": hashlib.sha256(raw).hexdigest(),
    }

    filename = path.name.lower()

    if filename == "bookmarks":
        return {
            "type": "chromium_bookmarks",
            "metadata": metadata,
            "data": _extract_bookmarks(raw),
        }

    if filename == "history":
        return {
            "type": "chromium_history",
            "metadata": metadata,
            "data": _extract_chromium_history(path),
        }

    if filename == "places.sqlite":
        return {
            "type": "firefox_places",
            "metadata": metadata,
            "data": _extract_firefox_places(path),
        }

    if filename == "cookies":
        return {
            "type": "chromium_cookies",
            "metadata": metadata,
            "data": _extract_chromium_cookies(path),
        }

    if filename == "cookies.sqlite":
        return {
            "type": "firefox_cookies",
            "metadata": metadata,
            "data": _extract_firefox_cookies(path),
        }

    if filename == "login data":
        return {
            "type": "chromium_login_metadata",
            "metadata": metadata,
            "data": _extract_chromium_logins(path),
        }

    if filename == "web data":
        return {
            "type": "chromium_web_data",
            "metadata": metadata,
            "data": _extract_web_data(path),
        }

    raise ValueError(f"Unsupported browser artefact: {path.name}")

def _connect_database(path):
    uri = path.resolve().as_uri() + "?mode=ro"
    connection = sqlite3.connect(uri, uri=True)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA query_only = ON")
    return connection

def _extract_chromium_history(path):
    with _connect_database(path) as connection:
        visits = connection.execute(
            """
            SELECT
                urls.id,
                urls.url,
                urls.title,
                urls.visit_count,
                urls.typed_count,
                urls.last_visit_time,
                visits.visit_time,
                visits.transition,
                visits.from_visit
            FROM urls
            LEFT JOIN visits ON urls.id = visits.url
            ORDER BY visits.visit_time DESC
            LIMIT ?
            """,
            (MAX_RECORDS,),
        ).fetchall()

        downloads = connection.execute(
            """
            SELECT
                id,
                guid,
                current_path,
                target_path,
                start_time,
                end_time,
                received_bytes,
                total_bytes,
                state,
                danger_type,
                interrupt_reason,
                opened
            FROM downloads
            ORDER BY start_time DESC
            LIMIT ?
            """,
            (MAX_RECORDS,),
        ).fetchall()

    return {
        "history": [
            {
                "url_id": row["id"],
                "url": row["url"],
                "title": row["title"],
                "visit_count": row["visit_count"],
                "typed_count": row["typed_count"],
                "last_visit_time": _chromium_time(row["last_visit_time"]),
                "visit_time": _chromium_time(row["visit_time"]),
                "transition": row["transition"],
                "from_visit": row["from_visit"],
            }
            for row in visits
        ],
        "downloads": [
            {
                "id": row["id"],
                "guid": row["guid"],
                "current_path": row["current_path"],
                "target_path": row["target_path"],
                "start_time": _chromium_time(row["start_time"]),
                "end_time": _chromium_time(row["end_time"]),
                "received_bytes": row["received_bytes"],
                "total_bytes": row["total_bytes"],
                "state": row["state"],
                "danger_type": row["danger_type"],
                "interrupt_reason": row["interrupt_reason"],
                "opened": bool(row["opened"]),
            }
            for row in downloads
        ],
    }

def _extract_firefox_places(path):
    with _connect_database(path) as connection:
        history = connection.execute(
            """
            SELECT
                p.id,
                p.url,
                p.title,
                p.visit_count,
                p.last_visit_date,
                h.visit_date,
                h.visit_type,
                h.from_visit
            FROM moz_places p
            LEFT JOIN moz_historyvisits h
                ON p.id = h.place_id
            ORDER BY h.visit_date DESC
            LIMIT ?
            """,
            (MAX_RECORDS,),
        ).fetchall()

        bookmarks = connection.execute(
            """
            SELECT
                b.id,
                b.type,
                b.fk,
                b.parent,
                b.position,
                b.title,
                b.dateAdded,
                b.lastModified,
                p.url
            FROM moz_bookmarks b
            LEFT JOIN moz_places p ON b.fk = p.id
            ORDER BY b.position
            LIMIT ?
            """,
            (MAX_RECORDS,),
        ).fetchall()

    return {
        "history": [
            {
                "id": row["id"],
                "url": row["url"],
                "title": row["title"],
                "visit_count": row["visit_count"],
                "last_visit": _unix_microseconds(row["last_visit_date"]),
                "visit_time": _unix_microseconds(row["visit_date"]),
                "visit_type": row["visit_type"],
                "from_visit": row["from_visit"],
            }
            for row in history
        ],
        "bookmarks": [
            {
                "id": row["id"],
                "type": row["type"],
                "place_id": row["fk"],
                "parent": row["parent"],
                "position": row["position"],
                "title": row["title"],
                "url": row["url"],
                "date_added": _unix_microseconds(row["dateAdded"]),
                "last_modified": _unix_microseconds(row["lastModified"]),
            }
            for row in bookmarks
        ],
    }

def _extract_chromium_cookies(path):
    with _connect_database(path) as connection:
        rows = connection.execute(
            """
            SELECT
                host_key,
                name,
                path,
                creation_utc,
                expires_utc,
                last_access_utc,
                is_secure,
                is_httponly,
                is_persistent,
                samesite,
                source_scheme,
                source_port,
                length(encrypted_value) AS encrypted_size,
                length(value) AS value_size
            FROM cookies
            ORDER BY host_key, name
            LIMIT ?
            """,
            (MAX_RECORDS,),
        ).fetchall()

    return [
        {
            "domain": row["host_key"],
            "name": row["name"],
            "path": row["path"],
            "created": _chromium_time(row["creation_utc"]),
            "expires": _chromium_time(row["expires_utc"]),
            "last_accessed": _chromium_time(row["last_access_utc"]),
            "secure": bool(row["is_secure"]),
            "http_only": bool(row["is_httponly"]),
            "persistent": bool(row["is_persistent"]),
            "same_site": row["samesite"],
            "source_scheme": row["source_scheme"],
            "source_port": row["source_port"],
            "encrypted_value_size": row["encrypted_size"],
            "value_size": row["value_size"],
        }
        for row in rows
    ]

def _extract_firefox_cookies(path):
    with _connect_database(path) as connection:
        rows = connection.execute(
            """
            SELECT
                id,
                originAttributes,
                name,
                value,
                host,
                path,
                expiry,
                lastAccessed,
                creationTime,
                isSecure,
                isHttpOnly,
                sameSite
            FROM moz_cookies
            ORDER BY host, name
            LIMIT ?
            """,
            (MAX_RECORDS,),
        ).fetchall()

    return [
        {
            "id": row["id"],
            "origin_attributes": row["originAttributes"],
            "name": row["name"],
            "value": row["value"],
            "domain": row["host"],
            "path": row["path"],
            "expires": _unix_seconds(row["expiry"]),
            "last_accessed": _unix_microseconds(row["lastAccessed"]),
            "created": _unix_microseconds(row["creationTime"]),
            "secure": bool(row["isSecure"]),
            "http_only": bool(row["isHttpOnly"]),
            "same_site": row["sameSite"],
        }
        for row in rows
    ]

def _extract_chromium_logins(path):
    with _connect_database(path) as connection:
        rows = connection.execute(
            """
            SELECT
                origin_url,
                action_url,
                username_element,
                username_value,
                password_element,
                date_created,
                date_last_used,
                date_password_modified,
                blacklisted_by_user,
                scheme
            FROM logins
            ORDER BY date_created DESC
            LIMIT ?
            """,
            (MAX_RECORDS,),
        ).fetchall()

    return [
        {
            "origin_url": row["origin_url"],
            "action_url": row["action_url"],
            "username_element": row["username_element"],
            "username": row["username_value"],
            "password_element": row["password_element"],
            "date_created": _chromium_time(row["date_created"]),
            "date_last_used": _chromium_time(row["date_last_used"]),
            "date_password_modified": _chromium_time(
                row["date_password_modified"]
            ),
            "blacklisted": bool(row["blacklisted_by_user"]),
            "scheme": row["scheme"],
            "password": None,
        }
        for row in rows
    ]

def _extract_web_data(path):
    with _connect_database(path) as connection:
        tables = connection.execute(
            """
            SELECT name
            FROM sqlite_master
            WHERE type = 'table'
            ORDER BY name
            """
        ).fetchall()

        available_tables = {
            row["name"] for row in tables
        }

        result = {}

        if "autofill" in available_tables:
            rows = connection.execute(
                """
                SELECT name, value, date_created, date_last_used, count
                FROM autofill
                LIMIT ?
                """,
                (MAX_RECORDS,),
            ).fetchall()

            result["autofill"] = [
                {
                    "name": row["name"],
                    "value": row["value"],
                    "date_created": _chromium_time(row["date_created"]),
                    "date_last_used": _chromium_time(row["date_last_used"]),
                    "count": row["count"],
                }
                for row in rows
            ]

        result["available_tables"] = sorted(available_tables)

    return result

def _extract_bookmarks(raw):
    try:
        document = json.loads(raw.decode("utf-8-sig"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("Invalid Chromium bookmarks JSON.") from exc

    roots = document.get("roots", {})

    return {
        "version": document.get("version"),
        "checksum": document.get("checksum"),
        "roots": {
            name: _bookmark_node(node)
            for name, node in roots.items()
        },
    }

def _bookmark_node(node, depth=0):
    if depth > 64:
        return {"error": "Maximum bookmark depth exceeded."}

    result = {
        "type": node.get("type"),
        "name": node.get("name"),
        "url": node.get("url"),
        "date_added": _chromium_time(
            int(node["date_added"]) if node.get("date_added") else None
        ),
        "date_modified": _chromium_time(
            int(node["date_modified"]) if node.get("date_modified") else None
        ),
    }

    children = node.get("children", [])

    if children:
        result["children"] = [
            _bookmark_node(child, depth + 1)
            for child in children[:MAX_RECORDS]
        ]

    return result

def _chromium_time(value):
    if not value:
        return None

    try:
        timestamp = (int(value) / 1_000_000) - 11644473600

        return datetime.fromtimestamp(
            timestamp,
            tz=timezone.utc,
        ).isoformat()
    except (ValueError, OverflowError, OSError):
        return None

def _unix_seconds(value):
    if value is None:
        return None

    try:
        return datetime.fromtimestamp(
            int(value),
            tz=timezone.utc,
        ).isoformat()
    except (ValueError, OverflowError, OSError):
        return None

def _unix_microseconds(value):
    if value is None:
        return None

    try:
        return datetime.fromtimestamp(
            int(value) / 1_000_000,
            tz=timezone.utc,
        ).isoformat()
    except (ValueError, OverflowError, OSError):
        return None