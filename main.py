from dotenv import load_dotenv

from core.identifier import Identifier, EntityType
from core.ip_responder import Responder
from tools.shodan import ShodanTool

load_dotenv()

def main() -> None:
    shodan = ShodanTool()

    identifier = Identifier(
        tools={
            EntityType.IP_ADDRESS: [
                shodan,
            ],
            EntityType.DOMAIN: [
                shodan,
            ],
        }
    )

    responder = Responder()

    while True:
        target = input("\nTarget: ").strip()

        if target.lower() == "q":
            print("Exiting.")
            break

        if not target:
            continue

        entity, results = identifier.process(target)

        print(f"\nType: {entity.type.value}")

        response = responder.respond(entity, results)

        print(f"\n{response}")

if __name__ == "__main__":
    main()