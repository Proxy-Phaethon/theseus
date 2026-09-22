import json
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from modules.commands.helpers.scraper import scrape

SEARXNG_URL = "http://localhost:8080/search"

def search(query):
    parameters = urlencode({
        "q": query,
        "format": "json"
    })

    url = f"{SEARXNG_URL}?{parameters}"

    request = Request(
        url,
        headers={
            "Accept": "application/json"
        }
    )

    with urlopen(request, timeout=10) as response:
        data = json.loads(response.read())

    return data.get("results", [])

def formulate_queries(investigation):
    target = investigation["target"]

    target_type = target["type"]
    target_name = target["name"]

    queries = []

    def add_query(query):
        query = query.strip()

        if query and query not in queries:
            queries.append(query)

    add_query(target_name)
    add_query(f"{target_type} {target_name}")

    return queries

def collect_sources(queries):
    sources = []
    seen_urls = set()

    for query in queries:
        results = search(query)

        for result in results:
            url = result.get("url")

            if not url or url in seen_urls:
                continue

            seen_urls.add(url)

            try:
                source = scrape(url)
            except Exception:
                continue

            if not source:
                continue

            content = source.get("content", "")

            if not content.strip():
                continue

            sources.append({
                "title": result.get("title"),
                "url": url,
                "content_type": source.get("content_type"),
                "content": content,
                "search_query": query,
            })

    return sources

def search_all(investigation):
    queries = formulate_queries(investigation)

    print("\nQueries:")

    for query in queries:
        print(f"  {query}")

    sources = collect_sources(queries)

    return {
        "investigation": investigation,
        "queries": queries,
        "sources": sources,
    }