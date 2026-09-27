from dotenv import load_dotenv

from core.identifier import Identifier
from core.normalizer import NormalizerRegistry

from collectors.registry import CollectorRegistry
from collectors.hibp import HIBPCollector
from collectors.searxng import SearXNGCollector
from collectors.crtsh import CRTShCollector
from collectors.urlscan import URLScanCollector
from collectors.shodan import ShodanCollector

from collectors.normalizers.shodan import ShodanNormalizer

from internet import Internet

load_dotenv()

def main() -> None:
    target = input("Target: ").strip()

    identifier = Identifier()
    entity = identifier.identify(target)

    print(f"\nEntity: {entity.value}")
    print(f"Type: {entity.type.value}")

    with Internet() as internet:
        collector_registry = CollectorRegistry()

        collector_registry.register(HIBPCollector(internet))
        collector_registry.register(SearXNGCollector(internet))
        collector_registry.register(CRTShCollector(internet))
        collector_registry.register(URLScanCollector(internet))
        collector_registry.register(ShodanCollector(internet))

        normalizer_registry = NormalizerRegistry()
        normalizer_registry.register(ShodanNormalizer())

        collectors = collector_registry.get(entity)

        print("\nCollectors:")
        for collector in collectors:
            print(f"  - {collector.name}")

        print()

        for collector in collectors:
            print(f"Running {collector.name}...")

            try:
                raw = collector.collect(entity)

                evidence = normalizer_registry.normalize(
                    collector.name,
                    entity,
                    raw,
                )

                for item in evidence:
                    print(item)

            except Exception as exc:
                print(f"Collector failed: {exc}")


if __name__ == "__main__":
    main()