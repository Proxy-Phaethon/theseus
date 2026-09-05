# for scraping, extraction, entity identification, source comparison, ranking, OSINT analysis, etc.
from command_helper import scraper

def process(operation, data):
    if operation == "SEARCH":
        return process_search(data)

    raise ValueError(f"Unknown operation: {operation}")

def process_search(url):
    page = scraper.scrape(url)

    return {
        "title": page["title"],
        "description": page["summary"],
        "url": page["url"]
    }