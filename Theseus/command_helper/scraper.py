import re
import requests

from bs4 import BeautifulSoup
from urllib.parse import urlparse

def scrape(url):
    headers = {
        "User-Agent": "Theseus/0.1"
    }

    response = requests.get(
        url,
        headers=headers,
        timeout=10
    )

    response.raise_for_status()

    soup = BeautifulSoup(
        response.text,
        "html.parser"
    )

    clean_html(soup)

    return {
        "url": url,
        "domain": urlparse(url).hostname,
        "title": extract_title(soup),
        "text": extract_text(soup),
        "author": extract_author(soup),
        "date": extract_date(soup)
    }

def clean_html(soup):
    for element in soup([
        "script",
        "style",
        "noscript",
        "nav",
        "footer",
        "header",
        "form",
        "aside",
        "iframe",
        "svg"
    ]):
        element.decompose()

def extract_title(soup):
    title = soup.find("title")

    if title:
        text = title.get_text(
            " ",
            strip=True
        )

        if text:
            return clean_text(text)

    return None

def extract_text(soup):
    paragraphs = []

    for paragraph in soup.find_all("p"):
        text = paragraph.get_text(
            " ",
            strip=True
        )

        text = clean_text(text)

        if text:
            paragraphs.append(text)

    if not paragraphs:
        return None

    return " ".join(paragraphs)

def extract_author(soup):
    author_tag = soup.find(
        "meta",
        attrs={"name": "author"}
    )

    if author_tag:
        author = author_tag.get("content")

        if author:
            return clean_text(author)

    return None

def extract_date(soup):
    date_properties = [
        "article:published_time",
        "article:modified_time"
    ]

    for property_name in date_properties:
        date_tag = soup.find(
            "meta",
            attrs={"property": property_name}
        )

        if date_tag:
            date = date_tag.get("content")

            if date:
                return date

    return None

def clean_text(text):
    text = re.sub(
        r"\s+",
        " ",
        text
    ).strip()

    return text