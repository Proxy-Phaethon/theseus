def respond(results):
    if not results:
        print("No results found.")
        return

    for index, result in enumerate(results, start=1):
        title = result.get("title", "Untitled")
        url = result.get("url", "")
        content = result.get("content", "")

        print(f"{index}. {title}")
        print(f"   {url}")

        if content:
            print(f"   {content}")

        print()