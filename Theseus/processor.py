# Scraping, extraction, entity identification,
# source comparison, ranking, and OSINT analysis.

from command_helper import scraper
from command_helper import reader

def process(operation, data):
    if operation == "SEARCH":
        return process_search(data)

    raise ValueError(f"Unknown operation: {operation}")

def process_search(data):
    query = data["query"]
    results = data["results"]

    if not results:
        return None

    pages = []

    for result in results:
        url = result.get("url")

        if not url:
            continue

        try:
            page = scraper.scrape(url)
        except Exception:
            continue

        if page:
            pages.append(page)

    if not pages:
        return None

    return reader.read(
        "SEARCH",
        query,
        pages
    )