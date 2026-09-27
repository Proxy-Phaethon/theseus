from dotenv import load_dotenv

from core.identifier import Identifier, EntityType
from core.responder import Responder
from tools.shodan import ShodanTool

load_dotenv()

def main() -> None:
    identifier = Identifier()
    responder = Responder()
    shodan = ShodanTool()

    while True:
        target = input("\nTarget: ").strip()

        if not target:
            continue

        if target.lower() in {"exit", "quit"}:
            break

        entity = identifier.identify(target)

        print(f"\nType: {entity.type.value}")

        if entity.type == EntityType.IP_ADDRESS:
            result = shodan.search_ip(entity.value)

        elif entity.type == EntityType.DOMAIN:
            result = shodan.search_domain(entity.value)

        else:
            print("No tool available for this target type.")
            continue

        response = responder.respond(result)

        print(f"\n{response}")

if __name__ == "__main__":
    main()