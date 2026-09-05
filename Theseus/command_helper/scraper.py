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

    return extract_page_data(soup, url)

def extract_page_data(soup, url):
    title = (
        soup.title.string.strip()
        if soup.title and soup.title.string
        else None
    )

    domain = urlparse(url).hostname

    text = soup.get_text(" ", strip=True)

    author = extract_author(soup)
    date = extract_date(soup)

    return {
        "url": url,
        "domain": domain,
        "title": title,
        "text": text,
        "author": author,
        "date": date
    }

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