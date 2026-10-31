import hashlib
import json
import shutil
import subprocess

from pathlib import Path

from mutagen import File as MutagenFile
from mutagen.id3 import APIC

from core.packets import Packet, PacketStatus

SUPPORTED_FORMATS = {
    ".mp3", ".wav", ".flac", ".aac", ".m4a",
    ".ogg", ".opus", ".wma", ".aiff", ".aif",
    ".ape", ".wv", ".mp4",
}

def _normalise_value(value):
    """Convert Mutagen metadata values into serialisable values."""

    if value is None:
        return None

    if isinstance(value, bytes):
        return value.hex()

    if isinstance(value, (list, tuple)):
        return [_normalise_value(item) for item in value]

    if isinstance(value, (str, int, float, bool)):
        return value

    if hasattr(value, "text"):
        return _normalise_value(value.text)

    if hasattr(value, "value"):
        return _normalise_value(value.value)

    return str(value)

def _extract_tags(tags):
    """Extract available metadata tags."""

    if not tags:
        return {}

    metadata = {}

    for key, value in tags.items():
        if isinstance(value, APIC):
            continue

        metadata[str(key)] = _normalise_value(value)

    return metadata

def _extract_artwork(audio):
    """Extract embedded artwork metadata without exporting image data."""

    artwork = []

    tags = audio.tags

    if not tags:
        return artwork

    # ID3 artwork, commonly used in MP3 files.
    if hasattr(tags, "getall"):
        for picture in tags.getall("APIC"):
            artwork.append({
                "mime_type": picture.mime,
                "description": picture.desc,
                "picture_type": picture.type,
                "size_bytes": len(picture.data),
            })

    # FLAC and other formats exposing picture objects.
    for picture in getattr(tags, "pictures", []):
        artwork.append({
            "mime_type": picture.mime,
            "description": picture.desc,
            "picture_type": picture.type,
            "size_bytes": len(picture.data),
        })

    # MP4/M4A embedded cover art.
    if "covr" in tags:
        for picture in tags["covr"]:
            artwork.append({
                "mime_type": getattr(picture, "imageformat", None),
                "description": "Embedded cover artwork",
                "picture_type": None,
                "size_bytes": len(picture),
            })

    return artwork

def _calculate_hashes(path):
    """Calculate hashes of the original audio file."""

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

def _extract_ffprobe(path):
    """Retrieve additional stream information when FFprobe is available."""

    ffprobe = shutil.which("ffprobe")

    if not ffprobe:
        return None

    command = [
        ffprobe,
        "-v", "error",
        "-show_format",
        "-show_streams",
        "-of", "json",
        str(path),
    ]

    completed = subprocess.run(
        command,
        capture_output=True,
        text=True,
        timeout=30,
        check=True,
    )

    return json.loads(completed.stdout)

def _extract_audio_info(info):
    """Extract common technical properties from Mutagen."""

    if info is None:
        return {}

    return {
        "length_seconds": getattr(info, "length", None),
        "bitrate": getattr(info, "bitrate", None),
        "sample_rate": getattr(info, "sample_rate", None),
        "channels": getattr(info, "channels", None),
        "bits_per_sample": getattr(info, "bits_per_sample", None),
        "codec": getattr(info, "codec", None),
        "encoder_info": getattr(info, "encoder_info", None),
        "encoder_settings": getattr(info, "encoder_settings", None),
    }


def audioextract(packet: Packet) -> Packet:
    """
    Extract metadata from an audio file.

    Input:
        A filesystem path to an audio file.

    Output:
        File metadata, audio properties, embedded tags,
        artwork metadata, stream information and hashes.
    """

    result = packet.child(
        stage="extraction",
        artefact_type="audio",
        status=PacketStatus.RUNNING,
    )

    try:
        if not isinstance(packet.input, str):
            raise TypeError("Audio input must be a filesystem path.")

        path = Path(packet.input.strip()).expanduser()

        if not path.exists():
            raise FileNotFoundError(
                f"Audio file does not exist: {path}"
            )

        if not path.is_file():
            raise ValueError("Input must reference a regular file.")

        extension = path.suffix.lower()

        if extension not in SUPPORTED_FORMATS:
            raise ValueError(
                f"Unsupported audio extension: {extension or 'None'}"
            )

        audio = MutagenFile(path)

        if audio is None:
            raise ValueError(
                "File could not be recognised as a supported audio format."
            )

        file_stat = path.stat()

        tags = _extract_tags(audio.tags)
        artwork = _extract_artwork(audio)
        audio_info = _extract_audio_info(audio.info)

        ffprobe_data = None
        ffprobe_error = None

        try:
            ffprobe_data = _extract_ffprobe(path)

        except subprocess.TimeoutExpired:
            ffprobe_error = "FFprobe timed out."

        except subprocess.CalledProcessError:
            ffprobe_error = "FFprobe could not process the file."

        except json.JSONDecodeError:
            ffprobe_error = "FFprobe returned invalid JSON."

        result.data = {
            "file": {
                "name": path.name,
                "extension": extension,
                "absolute_path": str(path.resolve()),
                "size_bytes": file_stat.st_size,
            },
            "audio": {
                "format": audio.__class__.__name__,
                **audio_info,
            },
            "metadata": {
                "tags": tags,
                "artwork": artwork,
                "artwork_count": len(artwork),
            },
            "streams": ffprobe_data,
            "ffprobe_error": ffprobe_error,
            "hashes": _calculate_hashes(path),
        }

        result.status = PacketStatus.SUCCESS

    except FileNotFoundError as exc:
        result.status = PacketStatus.FAILED
        result.add_error(
            code="AUDIO_FILE_NOT_FOUND",
            message=str(exc),
            component="extractors.audio",
        )

    except PermissionError as exc:
        result.status = PacketStatus.FAILED
        result.add_error(
            code="AUDIO_ACCESS_DENIED",
            message=str(exc),
            component="extractors.audio",
        )

    except (TypeError, ValueError) as exc:
        result.status = PacketStatus.FAILED
        result.add_error(
            code="INVALID_AUDIO_INPUT",
            message=str(exc),
            component="extractors.audio",
        )

    except Exception as exc:
        result.status = PacketStatus.FAILED
        result.add_error(
            code="AUDIO_EXTRACTION_FAILED",
            message=str(exc),
            component="extractors.audio",
        )

    return result