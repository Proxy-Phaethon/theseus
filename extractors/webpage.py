from __future__ import annotations

from urllib.parse import urljoin, urlsplit

from bs4 import BeautifulSoup

from core.packets import Packet, PacketStatus

def webpageextract(packet: Packet) -> Packet:
    """Extract structured information from HTML webpage source."""

    result = packet.child(
        stage="extraction",
        artefact_type="webpage",
        status=PacketStatus.RUNNING,
    )

    try:
        if not isinstance(packet.input, str):
            raise ValueError("Webpage input must be an HTML string.")

        html = packet.input.strip()

        if not html:
            raise ValueError("HTML input cannot be empty.")

        soup = BeautifulSoup(html, "html.parser")

        title = soup.title.get_text(strip=True) if soup.title else None

        description_tag = soup.find(
            "meta",
            attrs={"name": lambda value: value and value.lower() == "description"},
        )

        description = (
            description_tag.get("content")
            if description_tag
            else None
        )

        canonical_tag = soup.find("link", rel="canonical")
        canonical_url = (
            canonical_tag.get("href")
            if canonical_tag
            else None
        )

        base_tag = soup.find("base", href=True)
        base_url = base_tag.get("href") if base_tag else None

        def resolve_url(value: str | None) -> str | None:
            if not value:
                return None

            if base_url:
                return urljoin(base_url, value)

            return value

        links = []

        for tag in soup.find_all("a", href=True):
            links.append({
                "text": tag.get_text(" ", strip=True) or None,
                "href": resolve_url(tag.get("href")),
                "rel": tag.get("rel") or None,
                "target": tag.get("target"),
            })

        images = []

        for tag in soup.find_all("img"):
            images.append({
                "src": resolve_url(tag.get("src")),
                "alt": tag.get("alt"),
                "title": tag.get("title"),
                "width": tag.get("width"),
                "height": tag.get("height"),
            })

        scripts = []

        for tag in soup.find_all("script"):
            scripts.append({
                "src": resolve_url(tag.get("src")),
                "type": tag.get("type"),
                "async": tag.has_attr("async"),
                "defer": tag.has_attr("defer"),
                "inline": tag.string is not None and not tag.get("src"),
            })

        stylesheets = []

        for tag in soup.find_all(
            "link",
            href=True,
        ):
            rel = tag.get("rel") or []

            if "stylesheet" in rel:
                stylesheets.append({
                    "href": resolve_url(tag.get("href")),
                    "media": tag.get("media"),
                    "type": tag.get("type"),
                })

        headings = {}

        for level in range(1, 7):
            tag_name = f"h{level}"

            headings[tag_name] = [
                tag.get_text(" ", strip=True)
                for tag in soup.find_all(tag_name)
            ]

        result.data = {
            "title": title,
            "description": description,
            "language": soup.html.get("lang") if soup.html else None,
            "charset": (
                soup.find("meta", charset=True).get("charset")
                if soup.find("meta", charset=True)
                else None
            ),
            "canonical_url": canonical_url,
            "base_url": base_url,
            "headings": headings,
            "links": links,
            "images": images,
            "scripts": scripts,
            "stylesheets": stylesheets,
            "counts": {
                "links": len(links),
                "images": len(images),
                "scripts": len(scripts),
                "stylesheets": len(stylesheets),
            },
        }

        result.status = PacketStatus.SUCCESS

    except Exception as exc:
        result.status = PacketStatus.FAILED
        result.add_error(
            code="webpage_extraction_failed",
            message=str(exc),
            component="extractors.webpage",
        )

    return result