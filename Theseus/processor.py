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
    seen_urls = set()
    seen_text = set()

    for result in results:
        url = result.get("url")

        if not url:
            continue

        if url in seen_urls:
            continue

        seen_urls.add(url)

        try:
            page = scraper.scrape(url)

        except requests.RequestException:
            continue

        if page is None:
            continue

        title = page.get("title")
        summary = page.get("summary")
        text = page.get("text")

        if not title:
            continue

        if not summary and not text:
            continue

        content = text or summary

        if content:
            normalized_text = " ".join(content.lower().split())

            if normalized_text in seen_text:
                continue

            seen_text.add(normalized_text)

        processed_results.append({
            "title": title,
            "summary": summary,
            "text": text,
            "url": page["url"],
            "source": page["source"],
            "author": page["author"],
            "date": page["date"]
        })

    if not processed_results:
        return None

    summary = processed_results[0]["summary"]

    sources = []

    for result in processed_results:
        sources.append({
            "title": result["title"],
            "url": result["url"]
        })

    return {
        "summary": summary,
        "sources": sources
    }