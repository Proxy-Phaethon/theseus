import io

import requests
from bs4 import BeautifulSoup
from pypdf import PdfReader
from docx import Document

USER_AGENT = "Theseus/0.1"

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
    lines = []

    for line in text.splitlines():
        line = " ".join(line.split())

        if line:
            lines.append(line)

    return "\n".join(lines)

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

    return clean_text(soup.get_text("\n"))

def scrape_pdf(content):
    reader = PdfReader(io.BytesIO(content))

    pages = []

    for page in reader.pages:
        try:
            text = page.extract_text()
        except Exception:
            continue

        if text:
            pages.append(text)

    return clean_text("\n".join(pages))

def scrape_docx(content):
    document = Document(io.BytesIO(content))

    paragraphs = []

    for paragraph in document.paragraphs:
        if paragraph.text.strip():
            paragraphs.append(paragraph.text)

    return clean_text("\n".join(paragraphs))

def scrape(url):
    response = fetch(url)

    content_type = response.headers.get(
        "Content-Type",
        ""
    ).lower()

    if "text/html" in content_type:
        content = scrape_html(
            response.content.decode(
                response.encoding or "utf-8",
                errors="replace"
            )
        )

    elif "application/pdf" in content_type:
        content = scrape_pdf(response.content)

    elif "application/vnd.openxmlformats-officedocument.wordprocessingml.document" in content_type:
        content = scrape_docx(response.content)

    else:
        return None

    return {
        "url": url,
        "content_type": content_type,
        "content": content
    }