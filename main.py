from dotenv import load_dotenv

from core.identifier import Identifier, EntityType
from core.ip_responder import Responder
from core.domain_responder import DomainResponder
from tools.shodan import ShodanTool
from tools.ldns import LDNSTool
from tools.rdap import RDAPTool
from tools.xposedornot import XposedOrNotTool

load_dotenv()

def main() -> None:
    shodan = ShodanTool()
    ldns = LDNSTool()
    rdap = RDAPTool()
    xposedornot = XposedOrNotTool()

    identifier = Identifier(
        tools={
            EntityType.IP_ADDRESS: [
                shodan,
            ],
            EntityType.DOMAIN: [
                ldns,
                rdap,
            ],
            EntityType.EMAIL: [
                xposedornot,
            ],
        }
    )

    responder = Responder()
    domain_responder = DomainResponder()

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
            response = domain_responder.respond(results)
            print(f"\n{response}")
            continue

        response = responder.respond(entity, results)

        print(f"\n{response}")

if __name__ == "__main__":
    main()