from dotenv import load_dotenv

from core.identifier import Identifier, EntityType
from core.ip_responder import Responder
from core.domain_responder import DomainResponder
from core.email_responder import EmailResponder
from core.url_responder import URLResponder
from core.username_responder import UsernameResponder

from tools.shodan import ShodanTool
from tools.ldns import LDNSTool
from tools.rdap import RDAPTool
from tools.xposedornot import XposedOrNotTool
from tools.disify import DisifyTool
from tools.http import HTTPTool
from tools.dns import DNSTool
from tools.whatsmyname import WhatsMyNameTool

load_dotenv()

def main() -> None:
    shodan = ShodanTool()
    ldns = LDNSTool()
    rdap = RDAPTool()
    xposedornot = XposedOrNotTool()
    disify = DisifyTool()
    http = HTTPTool()
    dns = DNSTool()
    whatsmyname = WhatsMyNameTool()

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
            EntityType.URL: [
                http,
                dns,
            ],
            EntityType.USERNAME: [
                whatsmyname,
            ],
        }
    )

    responder = Responder()
    domain_responder = DomainResponder()
    email_responder = EmailResponder()
    url_responder = URLResponder()
    username_responder = UsernameResponder()

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
            response = email_responder.respond(results)
            print(f"\n{response}")
            continue

        if entity.type == EntityType.URL:
            response = url_responder.respond(results)
            print(f"\n{response}")
            continue

        if entity.type == EntityType.USERNAME:
            response = username_responder.respond(results)
            print(f"\n{response}")
            continue

        response = responder.respond(entity, results)

        print(f"\n{response}")

if __name__ == "__main__":
    main()