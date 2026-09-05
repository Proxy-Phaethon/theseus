# Parameters → execute operation
import requests

def execute(operation, parameters):
    if operation == "SEARCH":
        query = parameters["query"]

        return {
            "query": query,
            "results": search(query)
        }

    raise ValueError(f"Unknown operation: {operation}")

def search(query):
    response = requests.get(
        "http://localhost:8080/search",
        params={
            "q": query,
            "format": "json"
        }
    )

    response.raise_for_status()

    results = response.json()["results"]

    if not results:
        return None

    return [
        {
            "title": result.get("title"),
            "url": result.get("url")
        }
        for result in results
    ]