import requests
from bs4 import BeautifulSoup

def scrape(url):
    response = requests.get(
        url,
        timeout=10,
        headers={
            "User-Agent": "Theseus/0.1"
        }
    )

    response.raise_for_status()

    soup = BeautifulSoup(response.text, "html.parser")

    for element in soup(["script", "style", "noscript"]):
        element.decompose()

    text = soup.get_text(" ", strip=True)

    return text