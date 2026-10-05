from dotenv import load_dotenv
from alive_progress import alive_bar

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

STAGES = [
    "Identifying target",
    "Mapping infrastructure",
    "Querying network intelligence",
    "Checking exposure",
    "Inspecting certificates",
    "Checking reputation",
    "Checking threat intelligence",
    "Checking anonymization",
    "Correlating observations",
    "Compiling intelligence",
]

def investigate(identifier, target):
    result = []

    def worker():
        result.append(
            identifier.process(target)
        )

    thread = threading.Thread(
        target=worker
    )

    thread.start()

    with alive_bar(
        spinner="waves2",
        title="Investigating",
        bar=None,
        stats=False,
        elapsed=False,
        monitor=False,
    ) as bar:

        for stage in STAGES:
            if not thread.is_alive():
                break

            bar.text = stage

            end = time.time() + 0.45

            while time.time() < end:
                if not thread.is_alive():
                    break

                time.sleep(0.05)

        while thread.is_alive():
            bar.text = "Compiling intelligence"
            time.sleep(0.05)

    thread.join()

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

        entity, results = investigate(
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

        response = responder.respond(
            entity,
            results,
        )

        print(f"\n{response}")

if __name__ == "__main__":
    main()