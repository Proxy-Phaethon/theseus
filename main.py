from dotenv import load_dotenv

from core.identifier import Identifier
from collectors.registry import CollectorRegistry
from collectors.hibp import HIBPCollector
from internet import Internet

def main() -> None:
    load_dotenv()

    print("THESEUS")
    print("OSINT Investigation Tool")
    print()

    target = input("Target: ").strip()

    if not target:
        print("No target provided.")
        return

    identifier = Identifier()
    entity = identifier.identify(target)

    print()
    print(f"Target: {entity.value}")
    print(f"Type:   {entity.type.value}")

    with Internet() as internet:
        registry = CollectorRegistry()

        try:
            registry.register(
                HIBPCollector(internet)
            )
        except ValueError as exc:
            print(f"\nCollector unavailable: {exc}")
            return

        collectors = registry.get(entity)

        if not collectors:
            print("\nNo collectors support this entity.")
            return

        print("\nCollectors:")
        for collector in collectors:
            print(f"  - {collector.name}")

        print()

        for collector in collectors:
            print(f"Running {collector.name}...")

            try:
                results = collector.collect(entity)
                print(results)

            except Exception as exc:
                print(f"Collector failed: {exc}")

if __name__ == "__main__":
    main()