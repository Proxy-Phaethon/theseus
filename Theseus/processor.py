# for scraping, extraction, entity identification, source comparison, ranking, OSINT analysis, etc.
from bs4 import BeautifulSoup
from command_helper import scraper
from urllib.parse import urlparse

def process(operation, data):
    if operation == "SEARCH":
        return process_search(data)

    raise ValueError(f"Unknown operation: {operation}")

def is_wikipedia(url):
    hostname = urlparse(url).hostname

    if hostname is None:
        return False

    return (
        hostname == "wikipedia.org"
        or hostname.endswith(".wikipedia.org")
    )

def process_search(url):
    if not is_wikipedia(url):
        raise ValueError("Unsupported source")

    html = scraper.scrape(url)

    soup = BeautifulSoup(html, "html.parser")

    title = (
        soup.title.string.strip()
        if soup.title and soup.title.string
        else None
    )

    content = soup.find("div", id="mw-content-text")

    description = None

    if content:
        for paragraph in content.find_all("p"):
            text = paragraph.get_text(" ", strip=True)

            if text:
                description = text
                break

    return {
        "title": title,
        "description": description,
        "url": url
    }