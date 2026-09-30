from dotenv import load_dotenv

from core.identifier import Identifier, EntityType
from core.ip_responder import Responder
from tools.shodan import ShodanTool
from tools.ldns import LDNSTool
from tools.rdap import RDAPTool

load_dotenv()

def main() -> None:
    shodan = ShodanTool()
    ldns = LDNSTool()
    rdap = RDAPTool()

    identifier = Identifier(
        tools={
            EntityType.IP_ADDRESS: [
                shodan,
            ],
            EntityType.DOMAIN: [
                ldns,
                rdap,
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

        if entity.type == EntityType.DOMAIN:
            for tool_name, result in results:
                print(f"\n--- {tool_name} ---")
                print(result)

            continue

        response = responder.respond(entity, results)

        print(f"\n{response}")

if __name__ == "__main__":
    main()