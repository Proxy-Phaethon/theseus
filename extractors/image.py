import hashlib
import os

from datetime import datetime, timezone
from pathlib import Path

from PIL import Image, ExifTags, UnidentifiedImageError

from core.packets import Packet, PacketStatus

def _normalise_value(value):
    """Convert EXIF and image metadata values into serialisable values."""

    if isinstance(value, bytes):
        return value.hex()

    if isinstance(value, (tuple, list)):
        return [_normalise_value(item) for item in value]

    if isinstance(value, dict):
        return {
            str(key): _normalise_value(item)
            for key, item in value.items()
        }

    if isinstance(value, (str, int, float, bool)) or value is None:
        return value

    try:
        return float(value)
    except (TypeError, ValueError):
        return str(value)

def _extract_exif(image):
    """Extract available EXIF metadata."""

    exif = image.getexif()

    if not exif:
        return {}

    metadata = {}

    for tag_id, value in exif.items():
        tag_name = ExifTags.TAGS.get(tag_id, str(tag_id))
        metadata[tag_name] = _normalise_value(value)

    # GPS information is stored in a separate EXIF IFD.
    try:
        gps_info = exif.get_ifd(ExifTags.IFD.GPSInfo)

        if gps_info:
            metadata["GPSInfo"] = {
                ExifTags.GPSTAGS.get(tag_id, str(tag_id)):
                    _normalise_value(value)
                for tag_id, value in gps_info.items()
            }

    except (KeyError, AttributeError, TypeError, ValueError):
        pass

    return metadata

def _calculate_hashes(path):
    """Calculate hashes of the original image file."""

    digests = {
        algorithm: hashlib.new(algorithm)
        for algorithm in ("md5", "sha1", "sha256")
    }

    with path.open("rb") as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b""):
            for digest in digests.values():
                digest.update(chunk)

    return {
        algorithm: digest.hexdigest()
        for algorithm, digest in digests.items()
    }

def _extract_frames(image):
    """Extract basic metadata for each frame."""

    frames = []

    for frame_number in range(image.n_frames):
        image.seek(frame_number)

        frames.append({
            "frame_number": frame_number + 1,
            "width": image.width,
            "height": image.height,
            "duration_ms": image.info.get("duration"),
            "disposal_method": getattr(image, "disposal_method", None),
        })

    return frames

def imageextract(packet: Packet) -> Packet:
    """
    Extract metadata from an image file.

    Input:
        A filesystem path to an image.

    Output:
        Image properties, EXIF metadata, frame information,
        colour information, and cryptographic hashes.
    """

    result = packet.child(
        stage="extraction",
        artefact_type="image",
        status=PacketStatus.RUNNING,
    )

    try:
        if not isinstance(packet.input, str):
            raise TypeError("Image input must be a filesystem path.")

        path = Path(packet.input.strip()).expanduser()

        if not path.exists():
            raise FileNotFoundError(
                f"Image file does not exist: {path}"
            )

        if not path.is_file():
            raise ValueError("Input must reference a regular file.")

        file_stat = path.stat()

        with Image.open(path) as image:
            image_format = image.format
            image.verify()

        # Reopen because verify() invalidates the image object.
        with Image.open(path) as image:
            image.load()

            width, height = image.size
            frame_count = getattr(image, "n_frames", 1)
            is_animated = getattr(image, "is_animated", False)

            transparency = image.info.get("transparency")

            if isinstance(transparency, bytes):
                transparency = transparency.hex()

            frames = _extract_frames(image)

            exif = _extract_exif(image)

            icc_profile = image.info.get("icc_profile")

            result.data = {
                "file": {
                    "name": path.name,
                    "extension": path.suffix.lower() or None,
                    "absolute_path": str(path.resolve()),
                    "size_bytes": file_stat.st_size,
                },
                "image": {
                    "format": image_format,
                    "width": width,
                    "height": height,
                    "dimensions": f"{width}x{height}",
                    "aspect_ratio": (
                        round(width / height, 4)
                        if height else None
                    ),
                    "pixel_count": width * height,
                    "mode": image.mode,
                    "bands": list(image.getbands()),
                    "has_transparency": (
                        "A" in image.getbands()
                        or transparency is not None
                    ),
                    "transparency": _normalise_value(transparency),
                    "is_animated": is_animated,
                    "frame_count": frame_count,
                    "loop": image.info.get("loop"),
                    "duration_ms": image.info.get("duration"),
                    "dpi": _normalise_value(image.info.get("dpi")),
                },
                "metadata": {
                    "exif": exif,
                    "icc_profile": {
                        "present": icc_profile is not None,
                        "size_bytes": (
                            len(icc_profile)
                            if icc_profile is not None
                            else 0
                        ),
                        "sha256": (
                            hashlib.sha256(icc_profile).hexdigest()
                            if icc_profile is not None
                            else None
                        ),
                    },
                },
                "frames": frames,
                "hashes": _calculate_hashes(path),
            }

        result.status = PacketStatus.SUCCESS

    except FileNotFoundError as exc:
        result.status = PacketStatus.FAILED
        result.add_error(
            code="IMAGE_FILE_NOT_FOUND",
            message=str(exc),
            component="extractors.image",
        )

    except PermissionError as exc:
        result.status = PacketStatus.FAILED
        result.add_error(
            code="IMAGE_ACCESS_DENIED",
            message=str(exc),
            component="extractors.image",
        )

    except (TypeError, ValueError) as exc:
        result.status = PacketStatus.FAILED
        result.add_error(
            code="INVALID_IMAGE_INPUT",
            message=str(exc),
            component="extractors.image",
        )

    except UnidentifiedImageError as exc:
        result.status = PacketStatus.FAILED
        result.add_error(
            code="UNIDENTIFIED_IMAGE",
            message="The supplied file is not a recognised image.",
            component="extractors.image",
        )

    except Image.DecompressionBombError as exc:
        result.status = PacketStatus.FAILED
        result.add_error(
            code="IMAGE_DECOMPRESSION_LIMIT",
            message=str(exc),
            component="extractors.image",
        )

    except Exception as exc:
        result.status = PacketStatus.FAILED
        result.add_error(
            code="IMAGE_EXTRACTION_FAILED",
            message=str(exc),
            component="extractors.image",
        )

    return result