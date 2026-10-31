from pathlib import Path
import configparser
import hashlib
import os
import re
import struct
from datetime import datetime, timezone

from core.packets import Packet, PacketStatus

SUPPORTED_EXTENSIONS = {
    ".lnk",
    ".url",
    ".desktop",
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

def _decode_windows_string(data: bytes, unicode: bool) -> str:
    encoding = "utf-16-le" if unicode else "cp1252"

    return data.decode(
        encoding,
        errors="replace",
    ).rstrip("\x00")

def _extract_lnk(path: Path) -> dict:
    data = path.read_bytes()

    if len(data) < 76:
        raise ValueError("Invalid or truncated Windows shortcut.")

    header_size = struct.unpack_from("<I", data, 0)[0]

    if header_size != 0x4C:
        raise ValueError("Invalid Windows shortcut header.")

    if data[4:20] != bytes.fromhex(
        "0114020000000000C000000000000046"
    ):
        raise ValueError("Invalid Windows shortcut CLSID.")

    flags = struct.unpack_from("<I", data, 20)[0]
    attributes = struct.unpack_from("<I", data, 24)[0]

    file_size = struct.unpack_from("<I", data, 52)[0]
    icon_index = struct.unpack_from("<i", data, 56)[0]
    show_command = struct.unpack_from("<I", data, 60)[0]

    result = {
        "format": "Windows Shortcut",
        "target": None,
        "description": None,
        "relative_path": None,
        "working_directory": None,
        "command_line_arguments": None,
        "icon_location": None,
        "file_size": file_size,
        "icon_index": icon_index,
        "show_command": show_command,
        "flags": {
            "has_target_id_list": bool(flags & 0x01),
            "has_link_info": bool(flags & 0x02),
            "has_name": bool(flags & 0x04),
            "has_relative_path": bool(flags & 0x08),
            "has_working_directory": bool(flags & 0x10),
            "has_arguments": bool(flags & 0x20),
            "has_icon_location": bool(flags & 0x40),
            "is_unicode": bool(flags & 0x80),
        },
        "file_attributes": attributes,
    }

    offset = 76

    if flags & 0x01:
        if offset + 2 > len(data):
            raise ValueError("Truncated target ID list.")

        id_list_size = struct.unpack_from("<H", data, offset)[0]
        offset += 2 + id_list_size

    if flags & 0x02:
        if offset + 4 > len(data):
            raise ValueError("Truncated LinkInfo structure.")

        link_info_size = struct.unpack_from(
            "<I", data, offset
        )[0]

        if link_info_size < 0x1C or offset + link_info_size > len(data):
            raise ValueError("Invalid LinkInfo structure.")

        info = data[offset:offset + link_info_size]

        header_size = struct.unpack_from("<I", info, 4)[0]
        volume_offset = struct.unpack_from("<I", info, 12)[0]
        local_base_offset = struct.unpack_from("<I", info, 16)[0]
        network_offset = struct.unpack_from("<I", info, 20)[0]
        suffix_offset = struct.unpack_from("<I", info, 24)[0]

        local_base = None
        network_path = None
        common_suffix = None

        if local_base_offset:
            if header_size >= 0x24:
                unicode_offset = struct.unpack_from(
                    "<I", info, 28
                )[0]

                if unicode_offset:
                    end = info.find(b"\x00\x00", unicode_offset)

                    if end >= 0:
                        local_base = info[
                            unicode_offset:end
                        ].decode("utf-16-le", errors="replace")

            if local_base is None:
                end = info.find(b"\x00", local_base_offset)

                if end >= 0:
                    local_base = _decode_windows_string(
                        info[local_base_offset:end],
                        False,
                    )

        if network_offset:
            if network_offset + 4 <= len(info):
                network_size = struct.unpack_from(
                    "<I", info, network_offset
                )[0]

                if network_size >= 0x14 and (
                    network_offset + network_size <= len(info)
                ):
                    net = info[
                        network_offset:network_offset + network_size
                    ]

                    net_header_size = struct.unpack_from(
                        "<I", net, 4
                    )[0]

                    net_name_offset = struct.unpack_from(
                        "<I", net, 8
                    )[0]

                    net_name_unicode_offset = (
                        struct.unpack_from("<I", net, 20)[0]
                        if net_header_size >= 0x1C
                        else 0
                    )

                    if net_name_unicode_offset:
                        end = net.find(
                            b"\x00\x00",
                            net_name_unicode_offset,
                        )

                        if end >= 0:
                            network_path = net[
                                net_name_unicode_offset:end
                            ].decode(
                                "utf-16-le",
                                errors="replace",
                            )

                    elif net_name_offset:
                        end = net.find(b"\x00", net_name_offset)

                        if end >= 0:
                            network_path = _decode_windows_string(
                                net[net_name_offset:end],
                                False,
                            )

        if suffix_offset:
            if header_size >= 0x24:
                suffix_unicode_offset = struct.unpack_from(
                    "<I", info, 32
                )[0]

                if suffix_unicode_offset:
                    end = info.find(
                        b"\x00\x00",
                        suffix_unicode_offset,
                    )

                    if end >= 0:
                        common_suffix = info[
                            suffix_unicode_offset:end
                        ].decode("utf-16-le", errors="replace")

            if common_suffix is None:
                end = info.find(b"\x00", suffix_offset)

                if end >= 0:
                    common_suffix = _decode_windows_string(
                        info[suffix_offset:end],
                        False,
                    )

        if local_base:
            result["target"] = (
                local_base.rstrip("\\/")
                + (
                    "\\" + common_suffix.lstrip("\\/")
                    if common_suffix else ""
                )
            )
        elif network_path:
            result["target"] = (
                network_path.rstrip("\\/")
                + (
                    "\\" + common_suffix.lstrip("\\/")
                    if common_suffix else ""
                )
            )

        offset += link_info_size

    unicode = bool(flags & 0x80)

    string_fields = [
        ("has_name", "description"),
        ("has_relative_path", "relative_path"),
        ("has_working_directory", "working_directory"),
        ("has_arguments", "command_line_arguments"),
        ("has_icon_location", "icon_location"),
    ]

    for flag_name, field_name in string_fields:
        if not result["flags"][flag_name]:
            continue

        if offset + 2 > len(data):
            raise ValueError("Truncated shortcut string data.")

        count = struct.unpack_from("<H", data, offset)[0]
        offset += 2

        byte_count = count * (2 if unicode else 1)

        if offset + byte_count > len(data):
            raise ValueError("Invalid shortcut string length.")

        result[field_name] = _decode_windows_string(
            data[offset:offset + byte_count],
            unicode,
        )

        offset += byte_count

    if result["target"] is None:
        result["target"] = result["relative_path"]

    return result

def _extract_url(path: Path) -> dict:
    parser = configparser.ConfigParser(
        interpolation=None,
        strict=False,
    )

    parser.read(path, encoding="utf-8-sig")

    if not parser.has_section("InternetShortcut"):
        raise ValueError("Missing InternetShortcut section.")

    section = parser["InternetShortcut"]

    return {
        "format": "Windows Internet Shortcut",
        "target": section.get("URL"),
        "icon_file": section.get("IconFile"),
        "icon_index": section.getint("IconIndex", fallback=None),
        "hotkey": section.get("HotKey"),
        "modified": section.get("Modified"),
    }

def _extract_desktop(path: Path) -> dict:
    parser = configparser.ConfigParser(
        interpolation=None,
        strict=False,
    )

    parser.read(path, encoding="utf-8")

    if not parser.has_section("Desktop Entry"):
        raise ValueError("Missing Desktop Entry section.")

    section = parser["Desktop Entry"]

    return {
        "format": "Linux Desktop Entry",
        "name": section.get("Name"),
        "generic_name": section.get("GenericName"),
        "comment": section.get("Comment"),
        "type": section.get("Type"),
        "target": section.get("URL") or section.get("Exec"),
        "exec": section.get("Exec"),
        "working_directory": section.get("Path"),
        "icon": section.get("Icon"),
        "terminal": section.getboolean(
            "Terminal",
            fallback=None,
        ),
        "hidden": section.getboolean(
            "Hidden",
            fallback=None,
        ),
        "no_display": section.getboolean(
            "NoDisplay",
            fallback=None,
        ),
        "startup_notify": section.getboolean(
            "StartupNotify",
            fallback=None,
        ),
        "categories": [
            item for item in section.get(
                "Categories", ""
            ).split(";") if item
        ],
        "mime_types": [
            item for item in section.get(
                "MimeType", ""
            ).split(";") if item
        ],
        "actions": [
            item for item in section.get(
                "Actions", ""
            ).split(";") if item
        ],
    }

def shortcutextract(packet: Packet) -> Packet:
    result = packet.child(
        stage="extraction",
        artefact_type="shortcut",
        status=PacketStatus.RUNNING,
    )

    try:
        path = Path(packet.input).expanduser()

        if not path.exists():
            raise FileNotFoundError(
                f"Shortcut file not found: {path}"
            )

        if not path.is_file():
            raise ValueError("Input must be a file.")

        extension = path.suffix.lower()

        if extension == ".lnk":
            shortcut_data = _extract_lnk(path)
        elif extension == ".url":
            shortcut_data = _extract_url(path)
        elif extension == ".desktop":
            shortcut_data = _extract_desktop(path)
        else:
            raise ValueError(
                f"Unsupported shortcut extension: {extension}"
            )

        stat = path.stat()

        result.data = {
            "file": {
                "name": path.name,
                "extension": extension,
                "absolute_path": str(path.resolve()),
                "size_bytes": stat.st_size,
                "modified": datetime.fromtimestamp(
                    stat.st_mtime,
                    tz=timezone.utc,
                ).isoformat(),
            },
            "hashes": _hash_file(path),
            "shortcut": shortcut_data,
        }

        result.status = PacketStatus.SUCCESS

    except FileNotFoundError as exc:
        result.add_error(
            code="SHORTCUT_FILE_NOT_FOUND",
            message=str(exc),
            component="extractors.shortcut",
        )
        result.status = PacketStatus.FAILED

    except PermissionError as exc:
        result.add_error(
            code="SHORTCUT_ACCESS_DENIED",
            message=str(exc),
            component="extractors.shortcut",
        )
        result.status = PacketStatus.FAILED

    except (OSError, configparser.Error, struct.error) as exc:
        result.add_error(
            code="INVALID_SHORTCUT_FILE",
            message=str(exc),
            component="extractors.shortcut",
        )
        result.status = PacketStatus.FAILED

    except ValueError as exc:
        result.add_error(
            code="INVALID_SHORTCUT_INPUT",
            message=str(exc),
            component="extractors.shortcut",
        )
        result.status = PacketStatus.FAILED

    except Exception as exc:
        result.add_error(
            code="SHORTCUT_EXTRACTION_FAILED",
            message=str(exc),
            component="extractors.shortcut",
        )
        result.status = PacketStatus.FAILED

    return result