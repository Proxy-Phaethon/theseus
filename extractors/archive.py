from pathlib import Path
import bz2
import gzip
import hashlib
import lzma
import tarfile
import zipfile
import os
from datetime import datetime, timezone

from core.packets import Packet, PacketStatus

ARCHIVE_EXTENSIONS = {
    ".zip",
    ".tar",
    ".gz",
    ".tgz",
    ".bz2",
    ".tbz",
    ".tbz2",
    ".xz",
    ".txz",
}

MAX_ENTRIES = 10000

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

def _zip_extract(path: Path) -> dict:
    with zipfile.ZipFile(path, "r") as archive:
        entries = archive.infolist()

        if len(entries) > MAX_ENTRIES:
            raise ValueError(
                f"Archive contains more than {MAX_ENTRIES} entries."
            )

        files = []

        for entry in entries:
            files.append({
                "name": entry.filename,
                "size": entry.file_size,
                "compressed_size": entry.compress_size,
                "compression": entry.compress_type,
                "crc32": f"{entry.CRC:08x}",
                "modified": (
                    datetime(
                        *entry.date_time,
                        tzinfo=timezone.utc,
                    ).isoformat()
                ),
                "is_directory": entry.is_dir(),
                "is_encrypted": bool(entry.flag_bits & 0x1),
                "external_attributes": entry.external_attr,
            })

        return {
            "format": "ZIP",
            "comment": archive.comment.decode(
                "utf-8",
                errors="replace",
            ),
            "entry_count": len(entries),
            "entries": files,
            "total_uncompressed_size": sum(
                entry.file_size for entry in entries
            ),
            "total_compressed_size": sum(
                entry.compress_size for entry in entries
            ),
            "is_encrypted": any(
                entry.flag_bits & 0x1 for entry in entries
            ),
        }

def _tar_extract(path: Path) -> dict:
    with tarfile.open(path, "r:*") as archive:
        entries = archive.getmembers()

        if len(entries) > MAX_ENTRIES:
            raise ValueError(
                f"Archive contains more than {MAX_ENTRIES} entries."
            )

        files = []

        for entry in entries:
            if entry.isfile():
                entry_type = "file"
            elif entry.isdir():
                entry_type = "directory"
            elif entry.issym():
                entry_type = "symbolic_link"
            elif entry.islnk():
                entry_type = "hard_link"
            elif entry.ischr():
                entry_type = "character_device"
            elif entry.isblk():
                entry_type = "block_device"
            elif entry.isfifo():
                entry_type = "fifo"
            else:
                entry_type = "unknown"

            files.append({
                "name": entry.name,
                "size": entry.size,
                "modified": _timestamp(entry.mtime),
                "mode": oct(entry.mode),
                "owner_id": entry.uid,
                "group_id": entry.gid,
                "owner_name": entry.uname or None,
                "group_name": entry.gname or None,
                "type": entry_type,
                "link_target": entry.linkname or None,
                "is_sparse": bool(entry.sparse),
            })

        return {
            "format": "TAR",
            "entry_count": len(entries),
            "entries": files,
            "total_uncompressed_size": sum(
                entry.size for entry in entries if entry.isfile()
            ),
        }

def _compressed_extract(path: Path) -> dict:
    suffix = path.suffix.lower()

    if suffix == ".gz":
        opener = gzip.open
        archive_format = "GZIP"
    elif suffix == ".bz2":
        opener = bz2.open
        archive_format = "BZIP2"
    elif suffix == ".xz":
        opener = lzma.open
        archive_format = "XZ"
    else:
        raise ValueError("Unsupported compressed file format.")

    decompressed_size = 0
    digest = hashlib.sha256()

    with opener(path, "rb") as file:
        while True:
            chunk = file.read(1024 * 1024)

            if not chunk:
                break

            decompressed_size += len(chunk)
            digest.update(chunk)

    return {
        "format": archive_format,
        "decompressed_size": decompressed_size,
        "decompressed_sha256": digest.hexdigest(),
        "contains_multiple_files": False,
    }

def _detect_format(path: Path) -> str:
    name = path.name.lower()

    if name.endswith((".tar.gz", ".tgz", ".tar.bz2",
                      ".tbz", ".tbz2", ".tar.xz", ".txz")):
        return "tar"

    if name.endswith(".zip"):
        return "zip"

    if name.endswith(".tar"):
        return "tar"

    if name.endswith((".gz", ".bz2", ".xz")):
        return "compressed"

    raise ValueError(
        f"Unsupported archive extension: {path.suffix}"
    )

def archiveextract(packet: Packet) -> Packet:
    result = packet.child(
        stage="extraction",
        artefact_type="archive",
        status=PacketStatus.RUNNING,
    )

    try:
        path = Path(packet.input).expanduser()

        if not path.exists():
            raise FileNotFoundError(
                f"Archive file not found: {path}"
            )

        if not path.is_file():
            raise ValueError("Input must be a file.")

        archive_type = _detect_format(path)

        if archive_type == "zip":
            archive_data = _zip_extract(path)
        elif archive_type == "tar":
            archive_data = _tar_extract(path)
        else:
            archive_data = _compressed_extract(path)

        stat = path.stat()

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
            "archive": archive_data,
        }

        result.status = PacketStatus.SUCCESS

    except FileNotFoundError as exc:
        result.add_error(
            code="ARCHIVE_FILE_NOT_FOUND",
            message=str(exc),
            component="extractors.archive",
        )
        result.status = PacketStatus.FAILED

    except PermissionError as exc:
        result.add_error(
            code="ARCHIVE_ACCESS_DENIED",
            message=str(exc),
            component="extractors.archive",
        )
        result.status = PacketStatus.FAILED

    except (zipfile.BadZipFile, tarfile.TarError,
            gzip.BadGzipFile, EOFError, lzma.LZMAError,
            OSError) as exc:
        result.add_error(
            code="INVALID_ARCHIVE",
            message=str(exc),
            component="extractors.archive",
        )
        result.status = PacketStatus.FAILED

    except ValueError as exc:
        result.add_error(
            code="INVALID_ARCHIVE_INPUT",
            message=str(exc),
            component="extractors.archive",
        )
        result.status = PacketStatus.FAILED

    except Exception as exc:
        result.add_error(
            code="ARCHIVE_EXTRACTION_FAILED",
            message=str(exc),
            component="extractors.archive",
        )
        result.status = PacketStatus.FAILED

    return result