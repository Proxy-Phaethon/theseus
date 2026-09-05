# for scraping, extraction, entity identification, source comparison, ranking, OSINT analysis, etc.
import requests

from command_helper import scraper

def process(operation, data):
    if operation == "SEARCH":
        return process_search(data)

    raise ValueError(f"Unknown operation: {operation}")

def process_search(results):
    if results is None:
        return None

    processed_results = []

    for result in results:
        url = result.get("url")

        if not url:
            continue

        try:
            page = scraper.scrape(url)

        except requests.RequestException:
            continue

        if page is None:
            continue

        processed_results.append({
            "title": page["title"],
            "description": page["summary"],
            "url": page["url"],
            "source": page["source"]
        })

    if not processed_results:
        return None

    return processed_results