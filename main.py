from dotenv import load_dotenv
from alive_progress import alive_bar

import threading
import time

from core.identifier import Identifier, Entity, EntityType
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

def investigate(identifier, target, forced_type=None):
    result = []
    errors = []

    def worker():
        try:
            if forced_type is None:
                result.append(identifier.process(target))
            else:
                entity = Entity(target, forced_type)
                result.append((entity, identifier.run(entity)))
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