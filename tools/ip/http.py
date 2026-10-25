"""HTTP response intelligence for IP targets.

Uses the Python standard library only.
Collects HTTP response metadata and a bounded sample of response content.
Does not submit forms, follow redirects, or interact with authenticated sessions.

Only run against systems you own or are authorized to assess.
"""

from __future__ import annotations

import hashlib
import http.client
import ipaddress
import json
import re
import socket
import ssl
from datetime import datetime, timezone
from typing import Any

TIMEOUT = 4.0
MAX_BODY_BYTES = 4096
MAX_HEADER_VALUE_LENGTH = 1000
USER_AGENT = "Theseus-OSINT/0.7"

HTTP_PORTS = {
    80: "HTTP",
    443: "HTTPS",
    3000: "HTTP Alternate",
    5000: "HTTP Alternate",
    5001: "HTTPS Alternate",
    8000: "HTTP Alternate",
    8008: "HTTP Alternate",
    8080: "HTTP Alternate",
    8081: "HTTP Alternate",
    8443: "HTTPS Alternate",
    8888: "HTTP Alternate",
    9000: "HTTP Alternate",
    9200: "HTTP / Elasticsearch",
    9443: "HTTPS Alternate",
}

SECURITY_HEADERS = {
    "strict-transport-security": "HSTS",
    "content-security-policy": "Content Security Policy",
    "x-content-type-options": "MIME Sniffing Protection",
    "x-frame-options": "Clickjacking Protection",
    "referrer-policy": "Referrer Policy",
    "permissions-policy": "Permissions Policy",
    "cross-origin-opener-policy": "Cross-Origin Opener Policy",
    "cross-origin-resource-policy": "Cross-Origin Resource Policy",
    "cross-origin-embedder-policy": "Cross-Origin Embedder Policy",
}

INTERESTING_HEADERS = {
    "server",
    "date",
    "content-type",
    "content-length",
    "location",
    "last-modified",
    "etag",
    "via",
    "x-powered-by",
    "x-aspnet-version",
    "x-generator",
    "x-cache",
    "x-served-by",
    "x-request-id",
    "cf-ray",
    "x-amz-cf-id",
    "x-runtime",
    "alt-svc",
}

def _now() -> str:
    return datetime.now(timezone.utc).isoformat()

def _header_map(headers: Any) -> dict[str, str]:
    """Normalize headers while preserving the first occurrence of each name."""
    result: dict[str, str] = {}

    for name, value in headers:
        key = name.lower().strip()
        if key not in result:
            result[key] = str(value).strip()[:MAX_HEADER_VALUE_LENGTH]

    return result

def _security_headers(headers: dict[str, str]) -> dict[str, Any]:
    present = {}
    missing = []

    for header, description in SECURITY_HEADERS.items():
        if header in headers:
            present[header] = {
                "name": description,
                "value": headers[header],
            }
        else:
            missing.append(header)

    return {
        "present": present,
        "missing": missing,
        "note": (
            "Missing headers are observations, not automatic vulnerability "
            "findings. Their relevance depends on the application."
        ),
    }

def _technology_indicators(
    headers: dict[str, str],
    body: bytes,
) -> list[dict[str, str]]:
    """Extract cautious, evidence-backed technology indicators."""
    indicators: list[dict[str, str]] = []

    header_rules = {
        "server": "Server software disclosure",
        "x-powered-by": "Application runtime disclosure",
        "x-aspnet-version": "ASP.NET version disclosure",
        "x-generator": "Content management or generator disclosure",
        "x-runtime": "Application runtime disclosure",
    }

    for header, description in header_rules.items():
        if headers.get(header):
            indicators.append({
                "type": "header",
                "indicator": header,
                "value": headers[header],
                "description": description,
                "confidence": "header_observed",
            })

    text = body[:MAX_BODY_BYTES].decode("utf-8", errors="ignore")
    lower = text.lower()

    body_patterns = [
        (
            "WordPress",
            re.compile(r"""<meta[^>]+name=["']generator["'][^>]+
                           content=["'][^"']*wordpress""", re.I | re.X),
        ),
        (
            "Drupal",
            re.compile(r"""<meta[^>]+name=["']generator["'][^>]+
                           content=["'][^"']*drupal""", re.I | re.X),
        ),
        (
            "Joomla",
            re.compile(r"""<meta[^>]+name=["']generator["'][^>]+
                           content=["'][^"']*joomla""", re.I | re.X),
        ),
    ]

    for technology, pattern in body_patterns:
        if pattern.search(text):
            indicators.append({
                "type": "body_pattern",
                "indicator": technology,
                "value": "Generator metadata observed in response body",
                "description": "Possible content management system",
                "confidence": "metadata_hint",
            })

    if "wp-content/" in lower or "wp-includes/" in lower:
        indicators.append({
            "type": "body_pattern",
            "indicator": "WordPress path",
            "value": "wp-content or wp-includes reference",
            "description": "Possible WordPress-related content",
            "confidence": "path_hint",
        })

    if "cdn-cgi/" in lower or "cf-ray" in headers:
        indicators.append({
            "type": "header_or_body",
            "indicator": "Cloudflare",
            "value": "Cloudflare-related response indicator observed",
            "description": "Possible Cloudflare proxy or edge infrastructure",
            "confidence": "indicator_observed",
        })

    return indicators

def _request(
    address: str,
    port: int,
    use_tls: bool,
    verify_tls: bool,
) -> dict[str, Any]:
    """Make one bounded GET request without following redirects."""
    connection = None

    result: dict[str, Any] = {
        "port": port,
        "scheme": "https" if use_tls else "http",
        "service_guess": HTTP_PORTS[port],
        "status": "error",
        "http_status": None,
        "reason": None,
        "headers": {},
        "security_headers": None,
        "technology_indicators": [],
        "redirect": None,
        "body": None,
        "tls": None,
        "error": None,
    }

    try:
        if use_tls:
            context = (
                ssl.create_default_context()
                if verify_tls
                else ssl._create_unverified_context()
            )
            connection = http.client.HTTPSConnection(
                address,
                port=port,
                timeout=TIMEOUT,
                context=context,
            )
        else:
            connection = http.client.HTTPConnection(
                address,
                port=port,
                timeout=TIMEOUT,
            )

        connection.request(
            "GET",
            "/",
            body=None,
            headers={
                "Host": address,
                "User-Agent": USER_AGENT,
                "Accept": "*/*",
                "Accept-Encoding": "identity",
                "Connection": "close",
                "Range": f"bytes=0-{MAX_BODY_BYTES - 1}",
            },
        )

        response = connection.getresponse()
        body = response.read(MAX_BODY_BYTES)
        headers = _header_map(response.getheaders())

        result["status"] = "success"
        result["http_status"] = response.status
        result["reason"] = response.reason
        result["headers"] = {
            key: headers[key]
            for key in sorted(INTERESTING_HEADERS)
            if key in headers
        }
        result["security_headers"] = _security_headers(headers)

        if response.status in {301, 302, 303, 307, 308}:
            result["redirect"] = {
                "location": headers.get("location"),
                "followed": False,
            }

        content_type = headers.get("content-type", "")
        is_text = (
            content_type.startswith("text/")
            or "json" in content_type.lower()
            or "xml" in content_type.lower()
            or "javascript" in content_type.lower()
        )

        result["body"] = {
            "bytes_captured": len(body),
            "truncated_or_range_limited": (
                len(body) >= MAX_BODY_BYTES
                or response.status == 206
            ),
            "sha256": hashlib.sha256(body).hexdigest() if body else None,
            "content_type": content_type or None,
            "text_sample": (
                body.decode("utf-8", errors="replace")[:2000]
                if body and is_text
                else None
            ),
        }

        result["technology_indicators"] = _technology_indicators(
            headers,
            body if is_text else b"",
        )

        if use_tls and connection.sock:
            tls_sock = connection.sock
            cipher = tls_sock.cipher()
            result["tls"] = {
                "version": tls_sock.version(),
                "cipher_suite": cipher[0] if cipher else None,
                "certificate_verification": (
                    "passed" if verify_tls else "not_performed"
                ),
            }

    except ssl.SSLCertVerificationError as exc:
        result["status"] = "tls_verification_failed"
        result["error"] = {
            "type": type(exc).__name__,
            "message": str(exc),
            "verify_code": getattr(exc, "verify_code", None),
            "verify_message": getattr(exc, "verify_message", None),
        }
    except ssl.SSLError as exc:
        result["status"] = "tls_handshake_failed"
        result["error"] = {
            "type": type(exc).__name__,
            "message": str(exc),
        }
    except socket.timeout:
        result["status"] = "timeout"
        result["error"] = {
            "type": "Timeout",
            "message": f"Request exceeded {TIMEOUT} seconds",
        }
    except (ConnectionRefusedError, ConnectionResetError) as exc:
        result["status"] = "connection_failed"
        result["error"] = {
            "type": type(exc).__name__,
            "message": str(exc),
        }
    except (OSError, http.client.HTTPException, ValueError) as exc:
        result["status"] = "error"
        result["error"] = {
            "type": type(exc).__name__,
            "message": str(exc),
        }
    finally:
        if connection is not None:
            try:
                connection.close()
            except OSError:
                pass

    return result

def _inspect_port(address: str, port: int) -> dict[str, Any]:
    """Inspect a web port, retrying HTTPS without verification if needed."""
    use_tls = port in {443, 5001, 8443, 9443}

    result = _request(
        address=address,
        port=port,
        use_tls=use_tls,
        verify_tls=True,
    )

    if use_tls and result["status"] == "tls_verification_failed":
        verification_error = result["error"]

        retry = _request(
            address=address,
            port=port,
            use_tls=True,
            verify_tls=False,
        )
        retry["certificate_verification"] = {
            "status": "failed",
            "error": verification_error,
        }
        return retry

    if use_tls:
        result["certificate_verification"] = {
            "status": (
                "passed"
                if result["status"] == "success"
                else "not_completed"
            ),
        }

    return result

def run(target: str) -> dict[str, Any]:
    """Inspect HTTP-capable ports on a globally routable IP address."""
    timestamp = _now()

    try:
        address = ipaddress.ip_address(str(target).strip())
    except ValueError:
        return {
            "module": "http",
            "target": str(target),
            "status": "error",
            "error": "Invalid IP address",
            "timestamp": timestamp,
        }

    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        address = address.ipv4_mapped

    if not address.is_global:
        return {
            "module": "http",
            "target": str(address),
            "status": "not_checked",
            "reason": (
                "HTTP inspection is limited to globally routable IP addresses"
            ),
            "timestamp": timestamp,
        }

    canonical_target = str(address)
    results = [
        _inspect_port(canonical_target, port)
        for port in sorted(HTTP_PORTS)
    ]

    summary: dict[str, int] = {}
    for result in results:
        status = result["status"]
        summary[status] = summary.get(status, 0) + 1

    responding = [
        {
            "port": result["port"],
            "scheme": result["scheme"],
            "http_status": result["http_status"],
            "reason": result["reason"],
            "headers": result["headers"],
            "redirect": result["redirect"],
        }
        for result in results
        if result["status"] == "success"
    ]

    return {
        "module": "http",
        "target": canonical_target,
        "status": "success",
        "timestamp": timestamp,
        "source": "Direct HTTP requests",
        "scan": {
            "ports_tested": len(results),
            "timeout_seconds": TIMEOUT,
            "max_body_bytes": MAX_BODY_BYTES,
            "redirects_followed": False,
            "active_probing": True,
            "authorized_targets_only": True,
        },
        "summary": summary,
        "responding_endpoints": responding,
        "results": results,
        "limitations": [
            "Only predefined TCP ports are checked.",
            "No redirects are followed; Location headers are recorded only.",
            "A response from an IP may differ from the response for a hostname.",
            "TLS verification may fail when a certificate requires hostname-based SNI.",
            "Some servers ignore Range requests; response capture remains bounded.",
            "Technology indicators are hints, not definitive product identification.",
            "Missing security headers are not automatically vulnerabilities.",
            "No forms, authentication, or state-changing application actions are used.",
        ],
    }

def _now() -> str:
    return datetime.now(timezone.utc).isoformat()

if __name__ == "__main__":
    parser = __import__("argparse").ArgumentParser(
        description="Collect HTTP response intelligence for an authorized IP."
    )
    parser.add_argument("target", help="Target IP address")
    args = parser.parse_args()

    print(json.dumps(run(args.target), indent=2, ensure_ascii=False))