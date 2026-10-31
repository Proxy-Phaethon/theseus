from pathlib import Path
import hashlib
import json
import shutil
import subprocess
from datetime import datetime, timezone

from core.packets import Packet, PacketStatus

SUPPORTED_EXTENSIONS = {
    ".mp4", ".m4v", ".mkv", ".mov", ".avi",
    ".wmv", ".flv", ".webm", ".mpeg", ".mpg",
    ".m4p", ".3gp", ".3g2", ".ts", ".mts",
    ".m2ts", ".vob", ".ogv", ".asf",
}

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

def _run_ffprobe(path: Path) -> dict:
    command = [
        "ffprobe",
        "-v", "error",
        "-show_format",
        "-show_streams",
        "-show_chapters",
        "-of", "json",
        str(path),
    ]

    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        timeout=60,
        check=True,
    )

    return json.loads(result.stdout)

def _extract_streams(streams: list) -> dict:
    result = {
        "video": [],
        "audio": [],
        "subtitles": [],
        "data": [],
        "attachments": [],
        "other": [],
    }

    for stream in streams:
        stream_type = stream.get("codec_type", "other")

        if stream_type not in result:
            stream_type = "other"

        entry = {
            "index": stream.get("index"),
            "codec": stream.get("codec_name"),
            "codec_long_name": stream.get("codec_long_name"),
            "codec_tag": stream.get("codec_tag_string"),
            "profile": stream.get("profile"),
            "duration": stream.get("duration"),
            "bit_rate": stream.get("bit_rate"),
            "start_time": stream.get("start_time"),
            "time_base": stream.get("time_base"),
            "tags": stream.get("tags", {}),
            "disposition": stream.get("disposition", {}),
        }

        if stream_type == "video":
            entry.update({
                "width": stream.get("width"),
                "height": stream.get("height"),
                "coded_width": stream.get("coded_width"),
                "coded_height": stream.get("coded_height"),
                "display_aspect_ratio": stream.get(
                    "display_aspect_ratio"
                ),
                "sample_aspect_ratio": stream.get(
                    "sample_aspect_ratio"
                ),
                "frame_rate": stream.get("r_frame_rate"),
                "average_frame_rate": stream.get("avg_frame_rate"),
                "pixel_format": stream.get("pix_fmt"),
                "colour_space": stream.get("color_space"),
                "colour_transfer": stream.get("color_transfer"),
                "colour_primaries": stream.get("color_primaries"),
                "field_order": stream.get("field_order"),
            })

        elif stream_type == "audio":
            entry.update({
                "sample_rate": stream.get("sample_rate"),
                "channels": stream.get("channels"),
                "channel_layout": stream.get("channel_layout"),
                "sample_format": stream.get("sample_fmt"),
                "bits_per_sample": stream.get("bits_per_sample"),
            })

        elif stream_type == "subtitles":
            entry.update({
                "language": stream.get("tags", {}).get("language"),
            })

        result[stream_type].append(entry)

    return result

def videoextract(packet: Packet) -> Packet:
    result = packet.child(
        stage="extraction",
        artefact_type="video",
        status=PacketStatus.RUNNING,
    )

    try:
        path = Path(packet.input).expanduser()

        if not path.exists():
            raise FileNotFoundError(
                f"Video file not found: {path}"
            )

        if not path.is_file():
            raise ValueError(
                "Input must be a file."
            )

        if path.suffix.lower() not in SUPPORTED_EXTENSIONS:
            raise ValueError(
                f"Unsupported video extension: {path.suffix}"
            )

        if not shutil.which("ffprobe"):
            result.add_error(
                code="FFPROBE_NOT_INSTALLED",
                message=(
                    "FFprobe was not found. Install FFmpeg to "
                    "extract video metadata."
                ),
                component="extractors.video",
            )
            result.status = PacketStatus.NOT_SUPPORTED
            return result

        probe = _run_ffprobe(path)

        format_data = probe.get("format", {})
        streams = _extract_streams(probe.get("streams", []))

        stat = path.stat()

        result.data = {
            "file": {
                "name": path.name,
                "stem": path.stem,
                "extension": path.suffix.lower(),
                "absolute_path": str(path.resolve()),
                "size_bytes": stat.st_size,
                "modified": datetime.fromtimestamp(
                    stat.st_mtime,
                    tz=timezone.utc,
                ).isoformat(),
            },
            "hashes": _hash_file(path),
            "container": {
                "format_name": format_data.get("format_name"),
                "format_long_name": format_data.get("format_long_name"),
                "start_time": format_data.get("start_time"),
                "duration": format_data.get("duration"),
                "size": format_data.get("size"),
                "bit_rate": format_data.get("bit_rate"),
                "tags": format_data.get("tags", {}),
            },
            "streams": streams,
            "stream_counts": {
                stream_type: len(entries)
                for stream_type, entries in streams.items()
            },
            "chapters": probe.get("chapters", []),
        }

        result.status = PacketStatus.SUCCESS

    except FileNotFoundError as exc:
        result.add_error(
            code="VIDEO_FILE_NOT_FOUND",
            message=str(exc),
            component="extractors.video",
        )
        result.status = PacketStatus.FAILED

    except PermissionError as exc:
        result.add_error(
            code="VIDEO_ACCESS_DENIED",
            message=str(exc),
            component="extractors.video",
        )
        result.status = PacketStatus.FAILED

    except subprocess.TimeoutExpired:
        result.add_error(
            code="VIDEO_PROBE_TIMEOUT",
            message="FFprobe exceeded the 60-second timeout.",
            component="extractors.video",
        )
        result.status = PacketStatus.FAILED

    except subprocess.CalledProcessError as exc:
        result.add_error(
            code="VIDEO_PROBE_FAILED",
            message=exc.stderr.strip() or "FFprobe could not read the file.",
            component="extractors.video",
        )
        result.status = PacketStatus.FAILED

    except (ValueError, json.JSONDecodeError) as exc:
        result.add_error(
            code="INVALID_VIDEO_INPUT",
            message=str(exc),
            component="extractors.video",
        )
        result.status = PacketStatus.FAILED

    except Exception as exc:
        result.add_error(
            code="VIDEO_EXTRACTION_FAILED",
            message=str(exc),
            component="extractors.video",
        )
        result.status = PacketStatus.FAILED

    return result