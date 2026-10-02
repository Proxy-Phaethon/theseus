from dotenv import load_dotenv

from core.identifier import Identifier, EntityType
from core.ip_responder import Responder
from core.domain_responder import DomainResponder
from core.email_responder import EmailResponder

from tools.shodan import ShodanTool
from tools.ldns import LDNSTool
from tools.rdap import RDAPTool
from tools.xposedornot import XposedOrNotTool
from tools.disify import DisifyTool

load_dotenv()

def main() -> None:
    shodan = ShodanTool()
    ldns = LDNSTool()
    rdap = RDAPTool()
    xposedornot = XposedOrNotTool()
    disify = DisifyTool()

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
                disify,
            ],
        }
    )

    responder = Responder()
    domain_responder = DomainResponder()
    email_responder = EmailResponder()

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

        if entity.type == EntityType.EMAIL:
            print("\nRaw Results:")

            for tool_name, result in results:
                print(f"\n{tool_name}:")
                print(result)

            continue

        response = responder.respond(entity, results)

        print(f"\n{response}")

if __name__ == "__main__":
    main()