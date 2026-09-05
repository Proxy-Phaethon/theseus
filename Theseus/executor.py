# Parameters → execute operation

import requests

from command_helper import nlp

def execute(operation, parameters):
    if operation == "SEARCH":
        query = parameters["query"]

        terms = nlp.expand(query)

        print("[DEBUG] Expanded query:")
        for term in terms:
            print(f"  - {term}")

        return {
            "query": query,
            "results": search(terms)
        }

    raise ValueError(f"Unknown operation: {operation}")

def search(terms):
    results = []

    for term in terms:
        response = requests.get(
            "http://localhost:8080/search",
            params={
                "q": term,
                "format": "json"
            }
        )

        response.raise_for_status()

        data = response.json()
        search_results = data["results"]

        print(f"[DEBUG] Search term: {term}")
        print(f"[DEBUG] Results: {len(search_results)}")

        for result in search_results:
            results.append({
                "title": result.get("title"),
                "url": result.get("url"),
                "snippet": result.get("content")
            })

    if not results:
        return None

    return results