from internet.client import Client
from internet.page import Page

def main() -> None:
    print("THESEUS")
    print("OSINT Investigation Tool")
    print()

    target = input("Target: ").strip()

    if not target:
        print("No target provided.")
        return

    client = Client()

    try:
        response = client.get(target)

        page = Page(
            url=str(response.url),
            status=response.status_code,
            html=response.text,
        )

        print()
        print(f"URL:    {page.url}")
        print(f"STATUS: {page.status}")
        print(f"TITLE:  {page.title}")
        print()
        print(page.text)

    except Exception as exc:
        print(f"Error: {exc}")

    finally:
        client.close()

if __name__ == "__main__":
    main()