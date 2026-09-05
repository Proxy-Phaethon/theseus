import requests

def scrape(url):
    headers = {
        "User-Agent": "Theseus/0.1"
    }

    response = requests.get(
        url,
        headers=headers,
        timeout=10
    )

    response.raise_for_status()

    return response.text