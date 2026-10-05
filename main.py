from dotenv import load_dotenv

import itertools
import sys
import threading
import time

from core.identifier import Identifier, EntityType
from core.ip_responder import IPResponder
from core.domain_responder import DomainResponder
from core.email_responder import EmailResponder
from core.url_responder import URLResponder
from core.username_responder import UsernameResponder

from registry.collectors import build_collectors

load_dotenv()

def build_identifier() -> Identifier:
    return Identifier(
        tools=build_collectors()
    )

def build_responders():
    return {
        EntityType.IP_ADDRESS: IPResponder(),
        EntityType.DOMAIN: DomainResponder(),
        EntityType.EMAIL: EmailResponder(),
        EntityType.URL: URLResponder(),
        EntityType.USERNAME: UsernameResponder(),
    }

def run_with_spinner(identifier, target):
    result = []

    def worker():
        result.append(identifier.process(target))

    thread = threading.Thread(target=worker)
    thread.start()

    spinner = itertools.cycle(
        ["|", "/", "-", "\\"]
    )

    while thread.is_alive():
        sys.stdout.write(
            f"\rInvestigating {next(spinner)}"
        )
        sys.stdout.flush()
        time.sleep(0.1)

    thread.join()

    sys.stdout.write(
        "\r" + " " * 30 + "\r"
    )
    sys.stdout.flush()

    return result[0]

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

        entity, results = run_with_spinner(
            identifier,
            target,
        )

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