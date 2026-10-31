import hashlib
import mimetypes
import os
import stat

from pathlib import Path
from datetime import datetime, timezone

from core.packets import Packet, PacketStatus

def _timestamp(value):
    if value is None:
        return None

    return datetime.fromtimestamp(
        value,
        tz=timezone.utc,
    ).isoformat()

def _hash_file(path, algorithm):
    digest = hashlib.new(algorithm)

    with path.open("rb") as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b""):
            digest.update(chunk)

    return digest.hexdigest()

def fileextract(packet: Packet) -> Packet:
    """
    Extract filesystem metadata and cryptographic hashes.

    Input:
        A filesystem path to a file.

    Output:
        File metadata, timestamps, permissions, MIME type,
        and MD5, SHA1, and SHA256 hashes.
    """

    result = packet.child(
        stage="extraction",
        artefact_type="file",
        status=PacketStatus.RUNNING,
    )

    try:
        if not isinstance(packet.input, str):
            raise TypeError("File input must be a filesystem path.")

        path = Path(packet.input.strip()).expanduser()

        if not path.exists():
            raise FileNotFoundError(
                f"File does not exist: {path}"
            )

        if not path.is_file():
            raise ValueError("Input must reference a regular file.")

        file_stat = path.stat()
        mode = stat.S_IMODE(file_stat.st_mode)

        mime_type, mime_encoding = mimetypes.guess_type(
            path.name,
            strict=False,
        )

        hashes = {
            "md5": _hash_file(path, "md5"),
            "sha1": _hash_file(path, "sha1"),
            "sha256": _hash_file(path, "sha256"),
        }

        result.data = {
            "name": path.name,
            "stem": path.stem,
            "extension": path.suffix.lower() or None,
            "absolute_path": str(path.resolve()),
            "parent_directory": str(path.parent.resolve()),
            "size_bytes": file_stat.st_size,
            "size_human": _format_size(file_stat.st_size),
            "mime_type": mime_type,
            "mime_encoding": mime_encoding,
            "permissions": {
                "octal": oct(mode),
                "readable": os.access(path, os.R_OK),
                "writable": os.access(path, os.W_OK),
                "executable": os.access(path, os.X_OK),
            },
            "timestamps": {
                "created": _timestamp(
                    getattr(file_stat, "st_birthtime", None)
                ),
                "modified": _timestamp(file_stat.st_mtime),
                "accessed": _timestamp(file_stat.st_atime),
                "metadata_changed": _timestamp(file_stat.st_ctime),
            },
            "is_symlink": path.is_symlink(),
            "hashes": hashes,
        }

        result.status = PacketStatus.SUCCESS

    except FileNotFoundError as exc:
        result.status = PacketStatus.FAILED
        result.add_error(
            code="FILE_NOT_FOUND",
            message=str(exc),
            component="extractors.file",
        )

    except (TypeError, ValueError) as exc:
        result.status = PacketStatus.FAILED
        result.add_error(
            code="INVALID_FILE_INPUT",
            message=str(exc),
            component="extractors.file",
        )

    except PermissionError as exc:
        result.status = PacketStatus.FAILED
        result.add_error(
            code="FILE_PERMISSION_DENIED",
            message=str(exc),
            component="extractors.file",
        )

    except Exception as exc:
        result.status = PacketStatus.FAILED
        result.add_error(
            code="FILE_EXTRACTION_FAILED",
            message=str(exc),
            component="extractors.file",
        )

    return result

def _format_size(size):
    """Return a human-readable file size."""

    units = ("B", "KB", "MB", "GB", "TB")
    value = float(size)

    for unit in units:
        if value < 1024 or unit == units[-1]:
            return f"{value:.2f} {unit}"

        value /= 1024

    return f"{value:.2f} TB"