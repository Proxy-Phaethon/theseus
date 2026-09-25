from internet.client import Client
from internet.page import Page

def main() -> None:
    client = Client()

    try:
        response = client.get("https://example.com")

        page = Page(
            url=str(response.url),
            status=response.status_code,
            html=response.text,
        )

        print(f"URL: {page.url}")
        print(f"Status: {page.status}")
        print(f"Title: {page.title}")
        print()
        print(page.text)

    finally:
        client.close()

if __name__ == "__main__":
    main()