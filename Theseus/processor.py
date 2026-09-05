# for scraping, extraction, entity identification, source comparison, ranking, OSINT analysis, etc.
import requests

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

    pages = collect_pages(results)

    if not pages:
        return None

    pages = filter_pages(
        query,
        pages
    )

    if not pages:
        return None

    interpretation = reader.read(
        pages,
        query
    )

    if not interpretation:
        return None

    verified = verify(
        interpretation,
        pages
    )

    if not verified:
        return None

    return verified

def collect_pages(results):
    pages = []
    seen_urls = set()

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

        if page:
            pages.append(page)

    return pages

def filter_pages(query, pages):
    scored_pages = []

    query_words = set(
        query.lower().split()
    )

    for page in pages:
        text = page.get("text")

        if not text:
            continue

        text_words = set(
            text.lower().split()
        )

        score = len(
            query_words & text_words
        )

        scored_pages.append(
            (score, page)
        )

    scored_pages.sort(
        key=lambda item: item[0],
        reverse=True
    )

    return [
        page
        for score, page in scored_pages[:5]
        if score > 0
    ]

def verify(interpretation, pages):
    paragraph = interpretation.get("paragraph")

    if not paragraph:
        return None

    source_text = " ".join(
        page.get("text", "")
        for page in pages
    )

    if not source_text:
        return None

    source_text = source_text.lower()

    sentences = paragraph.split(".")

    for sentence in sentences:
        sentence = sentence.strip()

        if not sentence:
            continue

        words = set(
            sentence.lower().split()
        )

        words = {
            word.strip(" ,;:!?()[]{}")
            for word in words
            if len(word.strip(" ,;:!?()[]{}")) > 3
        }

        if not words:
            continue

        overlap = sum(
            word in source_text
            for word in words
        )

        confidence = overlap / len(words)

        if confidence < 0.6:
            return None

    return interpretation