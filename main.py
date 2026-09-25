from core.identifier import Identifier

def main() -> None:
    print("THESEUS")
    print("OSINT Investigation Tool")
    print()

    target = input("Target: ").strip()

    if not target:
        print("No target provided.")
        return

    identifier = Identifier()
    entity = identifier.identify(target)

    print(entity)

if __name__ == "__main__":
    main()