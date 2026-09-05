import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse

from command_helper.sources import SOURCES

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

    source = identify_source(url)

    if source is None:
        return extract_generic(soup, url)

    source_type = source["type"]

    if source_type == "encyclopedia":
        return extract_encyclopedia(soup, url, source)

    if source_type == "news":
        return extract_news(soup, url, source)

    if source_type == "international_organization":
        return extract_institutional(soup, url, source)

    return extract_generic(soup, url, source)

def identify_source(url):
    hostname = urlparse(url).hostname

    if hostname is None:
        return None

    for domain, source in SOURCES.items():
        if hostname == domain or hostname.endswith("." + domain):
            return source

    return None

def extract_encyclopedia(soup, url, source):
    content = soup.find("div", id="mw-content-text")

    summary = None
    text = None

    if content:
        paragraphs = get_paragraphs(content)

        if paragraphs:
            summary = paragraphs[0]
            text = " ".join(paragraphs)

    return build_result(
        soup,
        url,
        source,
        summary,
        text
    )

def extract_news(soup, url, source):
    article = (
        soup.find("article")
        or soup.find("main")
    )

    if article:
        paragraphs = get_paragraphs(article)
    else:
        paragraphs = get_paragraphs(soup)

    summary = paragraphs[0] if paragraphs else None
    text = " ".join(paragraphs) if paragraphs else None

    return build_result(
        soup,
        url,
        source,
        summary,
        text
    )

def extract_institutional(soup, url, source):
    content = (
        soup.find("main")
        or soup.find("article")
    )

    if content:
        paragraphs = get_paragraphs(content)
    else:
        paragraphs = get_paragraphs(soup)

    summary = paragraphs[0] if paragraphs else None
    text = " ".join(paragraphs) if paragraphs else None

    return build_result(
        soup,
        url,
        source,
        summary,
        text
    )

def extract_generic(soup, url, source=None):
    paragraphs = get_paragraphs(soup)

    summary = paragraphs[0] if paragraphs else None
    text = " ".join(paragraphs) if paragraphs else None

    return build_result(
        soup,
        url,
        source,
        summary,
        text
    )

def get_paragraphs(element):
    paragraphs = []

    for paragraph in element.find_all("p"):
        text = paragraph.get_text(" ", strip=True)

        if text:
            paragraphs.append(text)

    return paragraphs

def build_result(soup, url, source, summary, text):
    return {
        "url": url,
        "domain": urlparse(url).hostname,
        "source": source,
        "title": extract_title(soup),
        "summary": summary,
        "text": text,
        "author": extract_author(soup),
        "date": extract_date(soup)
    }

def extract_title(soup):
    if soup.title and soup.title.string:
        return soup.title.string.strip()

    return None

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