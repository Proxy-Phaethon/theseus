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

    soup = BeautifulSoup(response.text, "html.parser")

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
        "aside"
    ]):
        element.decompose()

def extract_title(soup):
    title = soup.find("title")

    if title:
        text = title.get_text(" ", strip=True)

        if text:
            return text

    return None

def extract_text(soup):
    paragraphs = []

    for paragraph in soup.find_all("p"):
        text = paragraph.get_text(" ", strip=True)

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
        return author_tag.get("content")

    return None

def extract_date(soup):
    date_tag = soup.find(
        "meta",
        attrs={"property": "article:published_time"}
    )

    if date_tag:
        return date_tag.get("content")

    return None