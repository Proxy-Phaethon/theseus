from dotenv import load_dotenv

from core.identifier import Identifier, EntityType
from core.ip_responder import Responder
from core.domain_responder import DomainResponder
from core.email_responder import EmailResponder
from core.url_responder import URLResponder
from core.username_responder import UsernameResponder

from tools.ip.shodan import ShodanTool
from tools.domain.ldns import LDNSTool
from tools.domain.rdap import RDAPTool
from tools.email.xposedornot import XposedOrNotTool
from tools.email.disify import DisifyTool
from tools.url.http import HTTPTool
from tools.url.dns import DNSTool
from tools.username.whatsmyname import WhatsMyNameTool

load_dotenv()

def build_identifier() -> Identifier:
    return Identifier(
        tools={
            EntityType.IP_ADDRESS: [
                ShodanTool(),
            ],
            EntityType.DOMAIN: [
                LDNSTool(),
                RDAPTool(),
            ],
            EntityType.EMAIL: [
                XposedOrNotTool(),
                DisifyTool(),
            ],
            EntityType.URL: [
                HTTPTool(),
                DNSTool(),
            ],
            EntityType.USERNAME: [
                WhatsMyNameTool(),
            ],
        }
    )


def build_responders():
    return {
        EntityType.IP_ADDRESS: Responder(),
        EntityType.DOMAIN: DomainResponder(),
        EntityType.EMAIL: EmailResponder(),
        EntityType.URL: URLResponder(),
        EntityType.USERNAME: UsernameResponder(),
    }


def main() -> None:
    identifier = build_identifier()
    responders = build_responders()

    while True:
        target = input("\n> ").strip()

        if target.lower() == "q":
            print("Exiting.")
            break

        if not target:
            continue

        entity, results = identifier.process(target)

        print(f"\nType: {entity.type.value}")

        responder = responders.get(entity.type)

        if responder is None:
            print(
                f"\nNo responder available for "
                f"{entity.type.value}."
            )
            continue

        response = responder.respond(entity, results)

        print(f"\n{response}")

if __name__ == "__main__":
    main()