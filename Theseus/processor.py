# for scraping, extraction, entity identification, source comparison, ranking, OSINT analysis, etc.

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

        if not page:
            continue

        pages.append({
            "url": url,
            "text": page.get("text", ""),
            "title": result.get("title"),
            "snippet": result.get("snippet")
        })

    if not pages:
        return None

    return reader.read(
        "SEARCH",
        query,
        pages
    )