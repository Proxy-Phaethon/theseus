from pathlib import Path
import os
import stat
import mimetypes
from datetime import datetime, timezone

from core.packets import Packet, PacketStatus

def _timestamp(value):
    if value is None:
        return None

    try:
        return datetime.fromtimestamp(
            value,
            tz=timezone.utc,
        ).isoformat()
    except (OSError, OverflowError, ValueError):
        return None

def _permissions(mode: int) -> dict:
    return {
        "octal": oct(stat.S_IMODE(mode)),
        "readable": bool(mode & stat.S_IRUSR),
        "writable": bool(mode & stat.S_IWUSR),
        "executable": bool(mode & stat.S_IXUSR),
        "setuid": bool(mode & stat.S_ISUID),
        "setgid": bool(mode & stat.S_ISGID),
        "sticky": bool(mode & stat.S_ISVTX),
    }

def _entry_metadata(path: Path, root: Path) -> dict:
    try:
        metadata = path.lstat()
    except OSError as exc:
        return {
            "name": path.name,
            "relative_path": str(path.relative_to(root)),
            "type": "unknown",
            "error": str(exc),
        }

    is_symlink = stat.S_ISLNK(metadata.st_mode)
    is_directory = stat.S_ISDIR(metadata.st_mode)
    is_file = stat.S_ISREG(metadata.st_mode)

    if is_symlink:
        entry_type = "symbolic_link"
    elif is_directory:
        entry_type = "directory"
    elif is_file:
        entry_type = "file"
    elif stat.S_ISSOCK(metadata.st_mode):
        entry_type = "socket"
    elif stat.S_ISFIFO(metadata.st_mode):
        entry_type = "fifo"
    elif stat.S_ISCHR(metadata.st_mode):
        entry_type = "character_device"
    elif stat.S_ISBLK(metadata.st_mode):
        entry_type = "block_device"
    else:
        entry_type = "unknown"

    mime_type = (
        mimetypes.guess_type(path.name)[0]
        if is_file else None
    )

    entry = {
        "name": path.name,
        "relative_path": str(path.relative_to(root)),
        "type": entry_type,
        "extension": path.suffix.lower() or None,
        "mime_type": mime_type,
        "size_bytes": metadata.st_size,
        "permissions": _permissions(metadata.st_mode),
        "modified": _timestamp(metadata.st_mtime),
        "accessed": _timestamp(metadata.st_atime),
        "created": _timestamp(
            getattr(metadata, "st_birthtime", None)
        ),
        "is_hidden": path.name.startswith("."),
        "is_symlink": is_symlink,
    }

    if is_symlink:
        try:
            entry["link_target"] = os.readlink(path)
        except OSError:
            entry["link_target"] = None

    return entry

def _scan_directory(root: Path, recursive: bool) -> dict:
    entries = []
    errors = []
    counts = {
        "files": 0,
        "directories": 0,
        "symbolic_links": 0,
        "other": 0,
    }

    total_file_size = 0

    def scan(current: Path):
        nonlocal total_file_size

        try:
            children = sorted(
                current.iterdir(),
                key=lambda item: item.name.lower(),
            )
        except PermissionError as exc:
            errors.append({
                "path": str(current.relative_to(root)),
                "error": str(exc),
            })
            return
        except OSError as exc:
            errors.append({
                "path": str(current.relative_to(root)),
                "error": str(exc),
            })
            return

        for child in children:
            entry = _entry_metadata(child, root)
            entries.append(entry)

            entry_type = entry["type"]

            if entry_type == "file":
                counts["files"] += 1
                total_file_size += entry.get("size_bytes", 0)

            elif entry_type == "directory":
                counts["directories"] += 1

            elif entry_type == "symbolic_link":
                counts["symbolic_links"] += 1

            else:
                counts["other"] += 1

            if (
                recursive
                and entry_type == "directory"
            ):
                scan(child)

    scan(root)

    return {
        "entries": entries,
        "counts": counts,
        "total_entries": len(entries),
        "total_file_size_bytes": total_file_size,
        "errors": errors,
    }

def directoryextract(packet: Packet) -> Packet:
    result = packet.child(
        stage="extraction",
        artefact_type="directory",
        status=PacketStatus.RUNNING,
    )

    try:
        root = Path(packet.input).expanduser()

        if not root.exists():
            raise FileNotFoundError(
                f"Directory not found: {root}"
            )

        if not root.is_dir():
            raise ValueError("Input must be a directory.")

        if root.is_symlink():
            raise ValueError(
                "The supplied root directory cannot be a symbolic link."
            )

        recursive = True
        scan_data = _scan_directory(root, recursive)

        result.data = {
            "directory": {
                "name": root.name or str(root),
                "absolute_path": str(root.resolve()),
                "recursive": recursive,
                "modified": _timestamp(root.stat().st_mtime),
            },
            **scan_data,
        }

        result.status = (
            PacketStatus.PARTIAL_SUCCESS
            if scan_data["errors"]
            else PacketStatus.SUCCESS
        )

    except FileNotFoundError as exc:
        result.add_error(
            code="DIRECTORY_NOT_FOUND",
            message=str(exc),
            component="extractors.directory",
        )
        result.status = PacketStatus.FAILED

    except PermissionError as exc:
        result.add_error(
            code="DIRECTORY_ACCESS_DENIED",
            message=str(exc),
            component="extractors.directory",
        )
        result.status = PacketStatus.FAILED

    except ValueError as exc:
        result.add_error(
            code="INVALID_DIRECTORY_INPUT",
            message=str(exc),
            component="extractors.directory",
        )
        result.status = PacketStatus.FAILED

    except OSError as exc:
        result.add_error(
            code="DIRECTORY_SCAN_FAILED",
            message=str(exc),
            component="extractors.directory",
        )
        result.status = PacketStatus.FAILED

    except Exception as exc:
        result.add_error(
            code="DIRECTORY_EXTRACTION_FAILED",
            message=str(exc),
            component="extractors.directory",
        )
        result.status = PacketStatus.FAILED

    return result