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
    return Identifier(tools=build_collectors())

def build_responders():
    return {
        EntityType.IP_ADDRESS: IPResponder(),
        EntityType.DOMAIN: DomainResponder(),
        EntityType.EMAIL: EmailResponder(),
        EntityType.URL: URLResponder(),
        EntityType.USERNAME: UsernameResponder(),
    }

STAGES = [
    "Identifying Target...",
    "Doing Somersaults...",
    "Zoning Out...",
    "Locking In...",
    "Drinking Tea...",
    "Checking Data...",
    "Petting Cats...",
    "Verifying Results...",
    "Concluding...",
    "Wait a Minute...",
    "Finding a Playlist...",
    "Contemplating Life...",
    "Trying to Figure Out...",
]

def investigate(identifier, target):
    result = []
    errors = []

    def worker():
        try:
            result.append(identifier.process(target))
        except Exception as exc:
            errors.append(exc)

    thread = threading.Thread(target=worker)
    thread.start()

    with alive_bar(
        1,
        spinner="waves2",
        bar=None,
        stats=False,
        elapsed=False,
        monitor=False,
    ) as bar:
        while thread.is_alive():
            for stage in STAGES:
                if not thread.is_alive():
                    break

                for i in range(1, len(stage) + 1):
                    if not thread.is_alive():
                        break
                    bar.text = stage[:i]
                    time.sleep(0.035)

                if thread.is_alive():
                    time.sleep(0.15)

                for i in range(len(stage) - 1, 0, -1):
                    if not thread.is_alive():
                        break
                    bar.text = stage[:i]
                    time.sleep(0.025)

        bar.text = "Compiling intelligence"
        time.sleep(1)

    thread.join()

    if errors:
        raise errors[0]
    if not result:
        raise RuntimeError("Investigation finished without returning results.")

    return result[0]

def print_all_subdomains(responder):
    subdomains = getattr(responder, "subdomains", [])
    if not subdomains:
        return

    answer = input(
        f"\nPrint all {len(subdomains)} discovered subdomains? [y/N]: "
    ).strip().lower()

    if answer not in {"y", "yes"}:
        return

    print("\nAll discovered subdomains:")
    for item in subdomains:
        if isinstance(item, dict):
            hostname = item.get("hostname")
            sources = item.get("sources", [])
            if not hostname:
                continue
            source_text = ", ".join(str(source) for source in sources if source)
            suffix = f" [{source_text}]" if source_text else ""
            print(f"  {hostname}{suffix}")
        else:
            print(f"  {item}")

def main() -> None:
    identifier = build_identifier()
    responders = build_responders()

    while True:
        target = input("\n> ").strip()

        if target.lower() in {
            "q", "q.", "quit", "quit.", "bye", "bye.", "exit", "exit."
        }:
            print("Exiting.")
            break

        if not target:
            continue

        try:
            entity, results = investigate(identifier, target)
        except Exception as exc:
            print(f"\nInvestigation failed: {exc}")
            continue

        print(f"\nType: {entity.type.value}")

        responder = responders.get(entity.type)
        if responder is None:
            print(f"\nNo responder available for {entity.type.value}.")
            continue

        response = responder.respond(entity, results)
        if response:
            print(f"\n{response}")
        else:
            print("\nNo reportable findings returned by the available collectors.")

        if entity.type == EntityType.DOMAIN:
            print_all_subdomains(responder)

if __name__ == "__main__":
    main()