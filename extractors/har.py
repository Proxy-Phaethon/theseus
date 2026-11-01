import base64
import hashlib
import json

from pathlib import Path
from urllib.parse import urlsplit, parse_qsl

from core.packets import Packet, PacketStatus

MAX_FILE_SIZE = 256 * 1024 * 1024
MAX_ENTRIES = 100000
MAX_HEADERS = 1000

def harextract(packet: Packet) -> Packet:
    result = packet.child(
        stage="extraction",
        artefact_type="har",
        status=PacketStatus.RUNNING,
    )

    try:
        source = packet.input

        if not isinstance(source, (str, Path)):
            raise ValueError("Input must be HAR JSON text or a file path.")

        raw, source_info = _load_source(source)

        try:
            document = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ValueError(
                f"Invalid HAR JSON: {exc}"
            ) from exc

        if not isinstance(document, dict):
            raise ValueError("HAR root must be a JSON object.")

        log = document.get("log")

        if not isinstance(log, dict):
            raise ValueError("HAR document does not contain a valid log object.")

        entries = log.get("entries", [])

        if not isinstance(entries, list):
            raise ValueError("HAR entries must be a list.")

        if len(entries) > MAX_ENTRIES:
            raise ValueError(
                f"HAR contains more than {MAX_ENTRIES} entries."
            )

        pages = log.get("pages", [])

        if not isinstance(pages, list):
            pages = []

        extracted_entries = [
            _extract_entry(entry, index)
            for index, entry in enumerate(entries)
        ]

        extracted_pages = [
            _extract_page(page, index)
            for index, page in enumerate(pages)
            if isinstance(page, dict)
        ]

        result.data = {
            "source": source_info,
            "har": {
                "version": log.get("version"),
                "creator": log.get("creator"),
                "browser": log.get("browser"),
                "comment": log.get("comment"),
                "pages": extracted_pages,
                "entries": extracted_entries,
                "statistics": _statistics(
                    extracted_entries,
                    extracted_pages,
                ),
            },
        }

        result.status = PacketStatus.SUCCESS

    except FileNotFoundError:
        result.status = PacketStatus.FAILED
        result.add_error(
            code="HAR_FILE_NOT_FOUND",
            message="The specified HAR file could not be found.",
            component="extractors.har",
        )

    except PermissionError:
        result.status = PacketStatus.FAILED
        result.add_error(
            code="HAR_PERMISSION_DENIED",
            message="Permission denied while reading the HAR file.",
            component="extractors.har",
        )

    except (OSError, ValueError, TypeError) as exc:
        result.status = PacketStatus.FAILED
        result.add_error(
            code="HAR_EXTRACTION_FAILED",
            message=str(exc),
            component="extractors.har",
        )

    except Exception as exc:
        result.status = PacketStatus.FAILED
        result.add_error(
            code="UNEXPECTED_ERROR",
            message=str(exc),
            component="extractors.har",
        )

    return result

def _load_source(source):
    candidate = str(source)

    if not candidate.lstrip().startswith(("{", "[")):
        path = Path(candidate).expanduser()

        if path.is_file():
            size = path.stat().st_size

            if size > MAX_FILE_SIZE:
                raise ValueError(
                    f"HAR file exceeds the {MAX_FILE_SIZE}-byte limit."
                )

            raw_bytes = path.read_bytes()

            try:
                raw = raw_bytes.decode("utf-8-sig")
            except UnicodeDecodeError as exc:
                raise ValueError(
                    "HAR file is not valid UTF-8."
                ) from exc

            return raw, {
                "type": "file",
                "path": str(path.resolve()),
                "size": size,
                "sha256": hashlib.sha256(raw_bytes).hexdigest(),
            }

    raw = candidate

    if not raw.strip():
        raise ValueError("HAR input is empty.")

    raw_bytes = raw.encode("utf-8")

    if len(raw_bytes) > MAX_FILE_SIZE:
        raise ValueError(
            f"HAR input exceeds the {MAX_FILE_SIZE}-byte limit."
        )

    return raw, {
        "type": "raw",
        "path": None,
        "size": len(raw_bytes),
        "sha256": hashlib.sha256(raw_bytes).hexdigest(),
    }

def _extract_entry(entry, index):
    if not isinstance(entry, dict):
        raise ValueError(
            f"HAR entry at index {index} must be an object."
        )

    request = entry.get("request", {})
    response = entry.get("response", {})
    timings = entry.get("timings", {})

    if not isinstance(request, dict):
        request = {}

    if not isinstance(response, dict):
        response = {}

    if not isinstance(timings, dict):
        timings = {}

    request_url = request.get("url")
    parsed_url = urlsplit(request_url) if isinstance(request_url, str) else None

    return {
        "index": index,
        "started_date_time": entry.get("startedDateTime"),
        "time": entry.get("time"),
        "pageref": entry.get("pageref"),
        "server_ip_address": entry.get("serverIPAddress"),
        "connection": entry.get("connection"),
        "request": {
            "method": request.get("method"),
            "url": request_url,
            "scheme": parsed_url.scheme if parsed_url else None,
            "hostname": parsed_url.hostname if parsed_url else None,
            "port": parsed_url.port if parsed_url else None,
            "path": parsed_url.path if parsed_url else None,
            "query_parameters": (
                parse_qsl(
                    parsed_url.query,
                    keep_blank_values=True,
                )
                if parsed_url
                else []
            ),
            "headers": _extract_headers(request.get("headers", [])),
            "cookies": _extract_cookies(request.get("cookies", [])),
            "headers_size": request.get("headersSize"),
            "body_size": request.get("bodySize"),
            "http_version": request.get("httpVersion"),
            "post_data": _extract_post_data(
                request.get("postData")
            ),
        },
        "response": {
            "status": response.get("status"),
            "status_text": response.get("statusText"),
            "http_version": response.get("httpVersion"),
            "headers": _extract_headers(response.get("headers", [])),
            "cookies": _extract_cookies(response.get("cookies", [])),
            "headers_size": response.get("headersSize"),
            "body_size": response.get("bodySize"),
            "redirect_url": response.get("redirectURL"),
            "content": _extract_content(
                response.get("content")
            ),
        },
        "timings": {
            "blocked": timings.get("blocked"),
            "dns": timings.get("dns"),
            "connect": timings.get("connect"),
            "send": timings.get("send"),
            "wait": timings.get("wait"),
            "receive": timings.get("receive"),
            "ssl": timings.get("ssl"),
        },
        "cache": entry.get("cache"),
        "comment": entry.get("comment"),
    }

def _extract_headers(headers):
    if not isinstance(headers, list):
        return []

    return [
        {
            "name": header.get("name"),
            "value": header.get("value"),
            "comment": header.get("comment"),
        }
        for header in headers[:MAX_HEADERS]
        if isinstance(header, dict)
    ]

def _extract_cookies(cookies):
    if not isinstance(cookies, list):
        return []

    return [
        {
            "name": cookie.get("name"),
            "value": cookie.get("value"),
            "path": cookie.get("path"),
            "domain": cookie.get("domain"),
            "expires": cookie.get("expires"),
            "http_only": cookie.get("httpOnly"),
            "secure": cookie.get("secure"),
            "same_site": cookie.get("sameSite"),
            "comment": cookie.get("comment"),
        }
        for cookie in cookies[:MAX_HEADERS]
        if isinstance(cookie, dict)
    ]

def _extract_post_data(post_data):
    if not isinstance(post_data, dict):
        return None

    return {
        "mime_type": post_data.get("mimeType"),
        "text": post_data.get("text"),
        "params": [
            {
                "name": item.get("name"),
                "value": item.get("value"),
                "file_name": item.get("fileName"),
                "content_type": item.get("contentType"),
            }
            for item in post_data.get("params", [])[:MAX_HEADERS]
            if isinstance(item, dict)
        ] if isinstance(post_data.get("params"), list) else [],
        "comment": post_data.get("comment"),
    }

def _extract_content(content):
    if not isinstance(content, dict):
        return None

    text = content.get("text")
    encoding = content.get("encoding")

    extracted = {
        "size": content.get("size"),
        "compression": content.get("compression"),
        "mime_type": content.get("mimeType"),
        "encoding": encoding,
        "text": text,
        "comment": content.get("comment"),
    }

    if isinstance(text, str) and encoding == "base64":
        try:
            decoded = base64.b64decode(
                text,
                validate=True,
            )

            extracted["decoded_size"] = len(decoded)
            extracted["decoded_sha256"] = hashlib.sha256(
                decoded
            ).hexdigest()

        except (ValueError, TypeError):
            extracted["decode_error"] = "Invalid Base64 content."

    return extracted

def _extract_page(page, index):
    return {
        "index": index,
        "started_date_time": page.get("startedDateTime"),
        "id": page.get("id"),
        "title": page.get("title"),
        "page_timings": page.get("pageTimings"),
        "comment": page.get("comment"),
    }

def _statistics(entries, pages):
    status_counts = {}
    method_counts = {}
    mime_counts = {}
    hostname_counts = {}

    total_time = 0
    total_request_bytes = 0
    total_response_bytes = 0

    for entry in entries:
        request = entry["request"]
        response = entry["response"]

        status = response["status"]
        method = request["method"]
        content = response["content"] or {}

        if status is not None:
            status_counts[str(status)] = (
                status_counts.get(str(status), 0) + 1
            )

        if method:
            method_counts[method] = (
                method_counts.get(method, 0) + 1
            )

        mime = content.get("mime_type")

        if mime:
            mime_counts[mime] = (
                mime_counts.get(mime, 0) + 1
            )

        hostname = request["hostname"]

        if hostname:
            hostname_counts[hostname] = (
                hostname_counts.get(hostname, 0) + 1
            )

        if isinstance(entry["time"], (int, float)):
            total_time += entry["time"]

        request_size = request.get("body_size")
        response_size = response.get("body_size")

        if isinstance(request_size, int) and request_size > 0:
            total_request_bytes += request_size

        if isinstance(response_size, int) and response_size > 0:
            total_response_bytes += response_size

    return {
        "total_entries": len(entries),
        "total_pages": len(pages),
        "status_codes": status_counts,
        "methods": method_counts,
        "mime_types": mime_counts,
        "hostnames": hostname_counts,
        "total_recorded_time_ms": total_time,
        "total_request_body_bytes": total_request_bytes,
        "total_response_body_bytes": total_response_bytes,
    }