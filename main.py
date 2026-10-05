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

class InvestigationLoader:
    FRAMES = ["◒", "◓", "◑", "◐"]

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

    def __init__(self):
        self.spinner = itertools.cycle(self.FRAMES)
        self.running = False
        self.thread = None
        self.process_result = None

    def run(self, identifier, target):
        self.running = True

        self.thread = threading.Thread(
            target=self._investigate,
            args=(identifier, target),
            daemon=True,
        )

        self.thread.start()

        self._animate()

        self.thread.join()

        return self.process_result

    def _investigate(self, identifier, target):
        self.process_result = identifier.process(target)

    def _animate(self):
        first_frame = True

        for stage in self.STAGES:
            if not self.running:
                break

            duration = 0.45

            end = time.time() + duration

            while time.time() < end:
                self._render(stage, first_frame)
                first_frame = False
                time.sleep(0.08)

        while self.thread.is_alive():
            self._render(
                "Compiling intelligence",
                first_frame,
            )

            first_frame = False
            time.sleep(0.08)

        self.running = False
        self._clear()

    def _render(self, stage, first_frame):
        frame = next(self.spinner)

        output = (
            "╭─ THESEUS ───────────────────────────────╮\n"
            f"│  {frame} {stage:<36} │\n"
            "│                                           │\n"
            "╰───────────────────────────────────────────╯"
        )

        if not first_frame:
            sys.stdout.write("\033[3A")

        sys.stdout.write(output)
        sys.stdout.flush()

    def _clear(self):
        sys.stdout.write("\033[3A")
        sys.stdout.write("\033[J")
        sys.stdout.flush()

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

        entity, results = InvestigationLoader().run(
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