from pathlib import Path
import hashlib
import math
from collections import Counter
from datetime import datetime, timezone

from core.packets import Packet, PacketStatus

HEADER_SIZE = 64
CHUNK_SIZE = 1024 * 1024

# Common file signatures (magic bytes).
SIGNATURES = {
    "ELF": b"\x7fELF",
    "PE/DOS executable": b"MZ",
    "PDF": b"%PDF-",
    "PNG": b"\x89PNG\r\n\x1a\n",
    "JPEG": b"\xff\xd8\xff",
    "GIF87a": b"GIF87a",
    "GIF89a": b"GIF89a",
    "ZIP": b"PK\x03\x04",
    "GZIP": b"\x1f\x8b",
    "BZIP2": b"BZh",
    "XZ": b"\xfd7zXZ\x00",
    "7-Zip": b"7z\xbc\xaf\x27\x1c",
    "RAR": b"Rar!\x1a\x07",
    "SQLite": b"SQLite format 3\x00",
    "WASM": b"\x00asm",
    "Java class": b"\xca\xfe\xba\xbe",
    "Mach-O 32-bit": b"\xfe\xed\xfa\xce",
    "Mach-O 64-bit": b"\xfe\xed\xfa\xcf",
    "Mach-O 32-bit (reversed)": b"\xce\xfa\xed\xfe",
    "Mach-O 64-bit (reversed)": b"\xcf\xfa\xed\xfe",
    "Mach-O Universal": b"\xca\xfe\xba\xbe",
}

def _hash_file(path: Path) -> dict:
    algorithms = {
        "md5": hashlib.md5(),
        "sha1": hashlib.sha1(),
        "sha256": hashlib.sha256(),
        "sha512": hashlib.sha512(),
    }

    with path.open("rb") as file:
        for chunk in iter(
            lambda: file.read(CHUNK_SIZE),
            b"",
        ):
            for algorithm in algorithms.values():
                algorithm.update(chunk)

    return {
        name: algorithm.hexdigest()
        for name, algorithm in algorithms.items()
    }

def _detect_signatures(header: bytes) -> list:
    matches = []

    for name, signature in SIGNATURES.items():
        if header.startswith(signature):
            matches.append(name)

    return matches

def _calculate_entropy(counter: Counter, total: int) -> float:
    if total == 0:
        return 0.0

    entropy = 0.0

    for count in counter.values():
        probability = count / total
        entropy -= probability * math.log2(probability)

    return round(entropy, 6)

def _inspect_bytes(path: Path) -> dict:
    byte_counts = Counter()
    total_bytes = 0
    null_bytes = 0
    printable_bytes = 0
    ascii_bytes = 0

    with path.open("rb") as file:
        while True:
            chunk = file.read(CHUNK_SIZE)

            if not chunk:
                break

            total_bytes += len(chunk)
            byte_counts.update(chunk)

            null_bytes += chunk.count(b"\x00")
            printable_bytes += sum(
                32 <= byte <= 126 or byte in (9, 10, 13)
                for byte in chunk
            )
            ascii_bytes += sum(
                byte < 128
                for byte in chunk
            )

    entropy = _calculate_entropy(
        byte_counts,
        total_bytes,
    )

    return {
        "entropy": entropy,
        "entropy_scale": "bits_per_byte",
        "null_bytes": null_bytes,
        "null_byte_ratio": (
            round(null_bytes / total_bytes, 6)
            if total_bytes else 0.0
        ),
        "printable_bytes": printable_bytes,
        "printable_byte_ratio": (
            round(printable_bytes / total_bytes, 6)
            if total_bytes else 0.0
        ),
        "ascii_bytes": ascii_bytes,
        "ascii_byte_ratio": (
            round(ascii_bytes / total_bytes, 6)
            if total_bytes else 0.0
        ),
        "unique_byte_values": len(byte_counts),
        "most_common_bytes": [
            {
                "byte": f"0x{value:02x}",
                "count": count,
            }
            for value, count in byte_counts.most_common(10)
        ],
    }

def _classify_format(signatures: list) -> str:
    if not signatures:
        return "Unknown"

    # Java class and Mach-O Universal share the same
    # initial four bytes. The signature alone is ambiguous.
    if signatures == ["Java class", "Mach-O Universal"]:
        return "Java class / Mach-O Universal"

    return signatures[0]

def binaryextract(packet: Packet) -> Packet:
    result = packet.child(
        stage="extraction",
        artefact_type="binary",
        status=PacketStatus.RUNNING,
    )

    try:
        path = Path(packet.input).expanduser()

        if not path.exists():
            raise FileNotFoundError(
                f"Binary file not found: {path}"
            )

        if not path.is_file():
            raise ValueError("Input must be a file.")

        stat = path.stat()

        with path.open("rb") as file:
            header = file.read(HEADER_SIZE)

        signatures = _detect_signatures(header)
        byte_analysis = _inspect_bytes(path)

        result.data = {
            "file": {
                "name": path.name,
                "extension": path.suffix.lower() or None,
                "absolute_path": str(path.resolve()),
                "size_bytes": stat.st_size,
                "modified": datetime.fromtimestamp(
                    stat.st_mtime,
                    tz=timezone.utc,
                ).isoformat(),
            },
            "signature": {
                "detected": signatures,
                "primary_format": _classify_format(signatures),
                "header_hex": header.hex(" "),
                "header_size": len(header),
            },
            "byte_analysis": byte_analysis,
            "hashes": _hash_file(path),
        }

        result.status = PacketStatus.SUCCESS

    except FileNotFoundError as exc:
        result.add_error(
            code="BINARY_FILE_NOT_FOUND",
            message=str(exc),
            component="extractors.binary",
        )
        result.status = PacketStatus.FAILED

    except PermissionError as exc:
        result.add_error(
            code="BINARY_ACCESS_DENIED",
            message=str(exc),
            component="extractors.binary",
        )
        result.status = PacketStatus.FAILED

    except OSError as exc:
        result.add_error(
            code="BINARY_READ_FAILED",
            message=str(exc),
            component="extractors.binary",
        )
        result.status = PacketStatus.FAILED

    except ValueError as exc:
        result.add_error(
            code="INVALID_BINARY_INPUT",
            message=str(exc),
            component="extractors.binary",
        )
        result.status = PacketStatus.FAILED

    except Exception as exc:
        result.add_error(
            code="BINARY_EXTRACTION_FAILED",
            message=str(exc),
            component="extractors.binary",
        )
        result.status = PacketStatus.FAILED

    return result