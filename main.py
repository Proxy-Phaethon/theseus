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
            EntityType.IP_ADDRESS: [shodan],
            EntityType.DOMAIN: [ldns, rdap],
            EntityType.EMAIL: [xposedornot, disify],
            EntityType.URL: [http, dns],
            EntityType.USERNAME: [whatsmyname],
        }
    )

    responders = {
        EntityType.IP_ADDRESS: Responder(),
        EntityType.DOMAIN: DomainResponder(),
        EntityType.EMAIL: EmailResponder(),
        EntityType.URL: URLResponder(),
        EntityType.USERNAME: UsernameResponder(),
    }

    while True:
        target = input("\nTarget: ").strip()

        if target.lower() == "q":
            print("Exiting.")
            break

        if not target:
            continue

        entity, results = identifier.process(target)

        responder = responders.get(entity.type)

        if responder is None:
            print(f"\nNo responder available for {entity.type.value}.")
            continue

        response = responder.respond(entity, results)

        print(f"\n{response}")

if __name__ == "__main__":
    main()