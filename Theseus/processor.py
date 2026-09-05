# for scraping, extraction, entity identification, source comparison, ranking, OSINT analysis, etc.
from urllib.parse import urlparse
from command_helper import scraper

def process(operation, data):
    if operation == "SEARCH":
        return process_search(data)

    raise ValueError(f"Unknown operation: {operation}")

def process_search(url):
    if not is_wikipedia(url):
        raise ValueError("Unsupported source")

    page = scraper.scrape(url)

    return {
        "title": page["title"],
        "description": page["summary"],
        "url": page["url"]
    }

def get_description(page):
    text = page["text"]

    if not text:
        return "No description available."

    return text

def is_wikipedia(url):
    hostname = urlparse(url).hostname

    if hostname is None:
        return False

    return (
        hostname == "wikipedia.org"
        or hostname.endswith(".wikipedia.org")
    )