from dotenv import load_dotenv

from core.identifier import Identifier, EntityType
from tools.shodan import ShodanTool

load_dotenv()

def main() -> None:
    identifier = Identifier()
    shodan = ShodanTool()

    while True:
        target = input("\nTarget: ").strip()

        if not target:
            continue

        if target.lower() in {"exit", "quit"}:
            break

        entity = identifier.identify(target)

        print(f"Type: {entity.type.value}")

        if entity.type == EntityType.IP_ADDRESS:
            result = shodan.search_ip(entity.value)

        elif entity.type == EntityType.DOMAIN:
            result = shodan.search_domain(entity.value)

        else:
            print("No tool available for this target type.")
            continue

        print(result)

if __name__ == "__main__":
    main()