import json
import spacy

from urllib.parse import urlencode
from urllib.request import Request, urlopen
from scraper import scrape

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

    def add_query(query):
        query = query.strip()

        if query and query not in queries:
            queries.append(query)

    add_query(original_query)

    for entity in entities:
        add_query(entity["text"])

    entity_texts = [entity["text"] for entity in entities]

    if entity_texts:
        add_query(" ".join(entity_texts))

    for entity in entity_texts:
        for keyword in keywords:
            if keyword.lower() != entity.lower():
                add_query(f"{entity} {keyword}")

    add_query(" ".join(keywords))

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

            url = result.get("url")

            if not url:
                continue

            try:
                result["content"] = scrape(url)
            except Exception:
                result["content"] = None

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

    return results