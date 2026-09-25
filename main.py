from internet import Internet

def main() -> None:
    print("THESEUS")
    print("OSINT Investigation Tool")
    print()

    target = input("Target: ").strip()

    if not target:
        print("No target provided.")
        return

    with Internet() as internet:
        try:
            page = internet.open(target)

            print()
            print(f"URL:    {page.url}")
            print(f"STATUS: {page.status}")
            print(f"TITLE:  {page.title}")
            print()
            print(page.text)

        except Exception as exc:
            print(f"Error: {exc}")

if __name__ == "__main__":
    main()