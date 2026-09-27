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

        if target.lower() == "q":
            print("Exiting.")
            break

        if not target:
            continue

        entity = identifier.identify(target)

        print(f"\nType: {entity.type.value}")

        if entity.type == EntityType.IP_ADDRESS:
            result = shodan.search_ip(entity.value)

        elif entity.type == EntityType.DOMAIN:
            result = shodan.search_domain(entity.value)

        else:
            print("No tool available for this target type.")
            continue

        response = responder.respond(entity, result)

        print(f"\n{response}")

if __name__ == "__main__":
    main()