import json
from urllib.parse import urlencode
from urllib.request import Request, urlopen

SEARXNG_URL = "http://localhost:8080/search"

def search(query):
    url = f"{SEARXNG_URL}?{urlencode({'q': query, 'format': 'json'})}"
    request = Request(url, headers={"Accept": "application/json"})

    with urlopen(request, timeout=10) as response:
        if not 200 <= response.status < 300:
            raise RuntimeError(f"Search request failed with status {response.status}")
        return json.loads(response.read())["results"]