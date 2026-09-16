import json
import spacy

from urllib.parse import urlencode
from urllib.request import Request, urlopen

SEARXNG_URL = "http://localhost:8080/search"

nlp = spacy.load("en_core_web_sm")

def understand_query(query):
    doc = nlp(query)

    entities = [
        {
            "text": entity.text,
            "label": entity.label_
        }
        for entity in doc.ents
    ]

    keywords = []

    for token in doc:
        if token.is_stop:
            continue

        if token.is_punct:
            continue

        if token.pos_ in {"NOUN", "PROPN", "ADJ", "VERB"}:
            keywords.append(token.text)

    return {
        "query": query,
        "entities": entities,
        "keywords": keywords
    }

def is_investigable(query_structure):
    entities = query_structure["entities"]
    keywords = query_structure["keywords"]

    if not entities and not keywords:
        return False

    return True

def formulate_queries(query_structure):
    original_query = query_structure["query"]
    entities = query_structure["entities"]
    keywords = query_structure["keywords"]

    queries = []

    queries.append(original_query)

    for entity in entities:
        entity_query = entity["text"]

        if entity_query not in queries:
            queries.append(entity_query)

    keyword_query = " ".join(keywords)

    if keyword_query and keyword_query not in queries:
        queries.append(keyword_query)

    return queries

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

def search_all(queries):
    results = []

    for query in queries:
        query_results = search(query)

        for result in query_results:
            result["search_query"] = query
            results.append(result)

    return results

def answer_query(query):
    query_structure = understand_query(query)

    if not is_investigable(query_structure):
        return None

    queries = formulate_queries(query_structure)

    results = search_all(queries)

    if not results:
        return None

    return f"Found {len(results)} results."