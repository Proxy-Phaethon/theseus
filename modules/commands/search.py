import json
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from modules.commands.helpers.scraper import scrape
from modules.commands.helpers.reader import read

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
    requests = investigation["requests"]

    target_type = target["type"]
    target_name = target["name"]

    queries = []

    def add_query(query):
        query = query.strip()

        if query and query not in queries:
            queries.append(query)

    add_query(target_name)

    add_query(f"{target_type} {target_name}")

    for request in requests:
        add_query(f"{target_name} {request}")
        add_query(f"{target_type} {target_name} {request}")

    return queries

def search_all(queries):
    results = []
    scraped_urls = set()

    for query in queries:
        query_results = search(query)

        for result in query_results:
            url = result.get("url")

            if not url:
                continue

            if url in scraped_urls:
                continue

            scraped_urls.add(url)

            try:
                source = scrape(url)

                if not source:
                    continue

                content = source.get("content", "")

                if not content.strip():
                    continue

            except Exception as error:
                continue

            results.append({
                "title": result.get("title"),
                "url": url,
                "content_type": source["content_type"],
                "content": content,
                "search_query": query,
            })

    return results

def answer_query(investigation):
    queries = formulate_queries(investigation)

    print("\nQueries:")
    for query in queries:
        print(f"  {query}")

    results = search_all(queries)

    if not results:
        return None

    answers = read(
        investigation,
        results
    )

    return {
        "investigation": investigation,
        "queries": queries,
        "answers": answers,
    }