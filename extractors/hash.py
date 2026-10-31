import hashlib
import re

from pathlib import Path

from core.packets import Packet, PacketStatus

HASH_ALGORITHMS = {
    "md5": 32,
    "sha1": 40,
    "sha224": 56,
    "sha256": 64,
    "sha384": 96,
    "sha512": 128,
}

def _identify_hash(value):
    """Identify supported hash algorithms by hexadecimal length."""

    if not re.fullmatch(r"[a-fA-F0-9]+", value):
        return None

    return [
        algorithm
        for algorithm, length in HASH_ALGORITHMS.items()
        if len(value) == length
    ]

def _calculate_hashes(path):
    """Calculate all supported hashes in a single file-reading pass."""

    digests = {
        algorithm: hashlib.new(algorithm)
        for algorithm in HASH_ALGORITHMS
    }

    with path.open("rb") as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b""):
            for digest in digests.values():
                digest.update(chunk)

    return {
        algorithm: digest.hexdigest()
        for algorithm, digest in digests.items()
    }

def hashextract(packet: Packet) -> Packet:
    """
    Identify a supplied hash or calculate hashes for a file.

    Input:
        A hexadecimal hash string or filesystem path.

    Output:
        Hash identification details or calculated file hashes.
    """

    result = packet.child(
        stage="extraction",
        artefact_type="hash",
        status=PacketStatus.RUNNING,
    )

    try:
        if not isinstance(packet.input, str):
            raise TypeError(
                "Hash input must be a hash string or filesystem path."
            )

        value = packet.input.strip()

        if not value:
            raise ValueError("Hash input cannot be empty.")

        # First check whether the input is a supported hash string.
        algorithms = _identify_hash(value)

        if algorithms:
            result.data = {
                "input_type": "hash",
                "value": value.lower(),
                "length": len(value),
                "encoding": "hexadecimal",
                "possible_algorithms": algorithms,
                "algorithm_identified": len(algorithms) == 1,
            }

            result.status = PacketStatus.SUCCESS
            return result

        # Otherwise, treat the input as a filesystem path.
        path = Path(value).expanduser()

        if not path.exists():
            raise FileNotFoundError(
                f"File does not exist: {path}"
            )

        if not path.is_file():
            raise ValueError("Input must reference a regular file.")

        hashes = _calculate_hashes(path)

        result.data = {
            "input_type": "file",
            "file": {
                "name": path.name,
                "absolute_path": str(path.resolve()),
                "size_bytes": path.stat().st_size,
            },
            "hashes": hashes,
            "algorithms": list(hashes.keys()),
        }

        result.status = PacketStatus.SUCCESS

    except FileNotFoundError as exc:
        result.status = PacketStatus.FAILED
        result.add_error(
            code="HASH_FILE_NOT_FOUND",
            message=str(exc),
            component="extractors.hash",
        )

    except (TypeError, ValueError) as exc:
        result.status = PacketStatus.FAILED
        result.add_error(
            code="INVALID_HASH_INPUT",
            message=str(exc),
            component="extractors.hash",
        )

    except PermissionError as exc:
        result.status = PacketStatus.FAILED
        result.add_error(
            code="HASH_PERMISSION_DENIED",
            message=str(exc),
            component="extractors.hash",
        )

    except Exception as exc:
        result.status = PacketStatus.FAILED
        result.add_error(
            code="HASH_EXTRACTION_FAILED",
            message=str(exc),
            component="extractors.hash",
        )

    return result