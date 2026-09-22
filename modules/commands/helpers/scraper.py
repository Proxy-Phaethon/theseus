import io
import re

import requests
from bs4 import BeautifulSoup
from docx import Document
from pypdf import PdfReader
import yt_dlp

USER_AGENT = "Theseus/0.1"

VIDEO_DOMAINS = (
    "youtube.com",
    "youtu.be",
    "vimeo.com",
    "dailymotion.com",
    "twitch.tv",
)

SOCIAL_DOMAINS = (
    "instagram.com",
    "facebook.com",
    "twitter.com",
    "x.com",
    "tiktok.com",
    "reddit.com",
    "threads.net",
)

def fetch(url):
    response = requests.get(
        url,
        timeout=15,
        headers={
            "User-Agent": USER_AGENT
        }
    )

    response.raise_for_status()

    return response

def clean_text(text):
    if not text:
        return ""

    lines = []

    for line in text.splitlines():
        line = " ".join(line.split())

        if line:
            lines.append(line)

    return "\n".join(lines)

def get_domain(url):
    url = url.lower()

    for domain in VIDEO_DOMAINS + SOCIAL_DOMAINS:
        if domain in url:
            return domain

    return None

def scrape_html(content):
    soup = BeautifulSoup(content, "html.parser")

    for element in soup([
        "script",
        "style",
        "noscript",
        "nav",
        "footer",
        "header"
    ]):
        element.decompose()

    title = ""

    if soup.title:
        title = clean_text(
            soup.title.get_text()
        )

    text = clean_text(
        soup.get_text("\n")
    )

    return {
        "title": title,
        "content": text
    }

def scrape_pdf(content):
    reader = PdfReader(
        io.BytesIO(content)
    )

    pages = []

    for page in reader.pages:
        text = page.extract_text()

        if text:
            pages.append(text)

    return clean_text(
        "\n".join(pages)
    )

def scrape_docx(content):
    document = Document(
        io.BytesIO(content)
    )

    paragraphs = []

    for paragraph in document.paragraphs:
        text = paragraph.text.strip()

        if text:
            paragraphs.append(text)

    return clean_text(
        "\n".join(paragraphs)
    )

def clean_subtitle(text):
    text = re.sub(
        r"^\d+$",
        "",
        text,
        flags=re.MULTILINE
    )

    text = re.sub(
        r"\d{2}:\d{2}:\d{2}[.,]\d{3}\s+-->\s+\d{2}:\d{2}:\d{2}[.,]\d{3}",
        "",
        text
    )

    text = re.sub(
        r"<[^>]+>",
        "",
        text
    )

    return clean_text(text)

def get_transcript(info):
    subtitle_sets = [
        info.get("subtitles", {}),
        info.get("automatic_captions", {})
    ]

    for subtitles in subtitle_sets:
        if not subtitles:
            continue

        tracks = (
            subtitles.get("en")
            or subtitles.get("en-US")
            or subtitles.get("en-GB")
        )

        if not tracks:
            continue

        for track in tracks:
            subtitle_url = track.get("url")

            if not subtitle_url:
                continue

            try:
                response = requests.get(
                    subtitle_url,
                    timeout=15,
                    headers={
                        "User-Agent": USER_AGENT
                    }
                )

                response.raise_for_status()

                transcript = clean_subtitle(
                    response.text
                )

                if transcript:
                    return transcript

            except requests.RequestException:
                continue

    return ""

def scrape_media(url):
    options = {
        "quiet": True,
        "no_warnings": True,
        "skip_download": True,
        "noprogress": True,
    }

    with yt_dlp.YoutubeDL(options) as ydl:
        info = ydl.extract_info(
            url,
            download=False
        )

    transcript = get_transcript(info)

    description = clean_text(
        info.get("description", "")
    )

    title = clean_text(
        info.get("title", "")
    )

    content_parts = []

    if title:
        content_parts.append(title)

    if description:
        content_parts.append(description)

    if transcript:
        content_parts.append(transcript)

    return {
        "url": url,
        "content_type": "media",
        "source_type": "video",
        "content": "\n".join(content_parts),
        "metadata": {
            "title": title,
            "description": description,
            "channel": info.get("channel"),
            "uploader": info.get("uploader"),
            "upload_date": info.get("upload_date"),
            "duration": info.get("duration"),
            "view_count": info.get("view_count"),
            "like_count": info.get("like_count"),
            "platform": info.get("extractor_key"),
            "transcript_available": bool(transcript),
        }
    }

def scrape_image(content, content_type):
    try:
        import pytesseract
        from PIL import Image

        image = Image.open(
            io.BytesIO(content)
        )

        text = pytesseract.image_to_string(
            image
        )

    except Exception:
        text = ""

    return {
        "content": clean_text(text),
        "content_type": content_type,
        "source_type": "image",
    }

def scrape_web(url, response):
    result = scrape_html(
        response.content.decode(
            response.encoding or "utf-8",
            errors="replace"
        )
    )

    return {
        "url": url,
        "content_type": response.headers.get(
            "Content-Type",
            ""
        ).lower(),
        "source_type": "webpage",
        "content": result["content"],
        "metadata": {
            "title": result["title"],
        }
    }

def scrape(url):
    domain = get_domain(url)

    if domain in VIDEO_DOMAINS:
        try:
            return scrape_media(url)
        except Exception:
            return None

    response = fetch(url)

    content_type = response.headers.get(
        "Content-Type",
        ""
    ).lower()

    if "text/html" in content_type:
        return scrape_web(
            url,
            response
        )

    if "application/pdf" in content_type:
        return {
            "url": url,
            "content_type": content_type,
            "source_type": "pdf",
            "content": scrape_pdf(
                response.content
            ),
        }

    if (
        "application/vnd.openxmlformats-officedocument"
        ".wordprocessingml.document"
        in content_type
    ):
        return {
            "url": url,
            "content_type": content_type,
            "source_type": "docx",
            "content": scrape_docx(
                response.content
            ),
        }

    if content_type.startswith("image/"):
        result = scrape_image(
            response.content,
            content_type
        )

        return {
            "url": url,
            **result,
        }

    if content_type.startswith("audio/"):
        return {
            "url": url,
            "content_type": content_type,
            "source_type": "audio",
            "content": "",
            "metadata": {},
        }

    if content_type.startswith("video/"):
        return {
            "url": url,
            "content_type": content_type,
            "source_type": "video",
            "content": "",
            "metadata": {},
        }

    return None