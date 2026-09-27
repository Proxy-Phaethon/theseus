from dotenv import load_dotenv

from core.identifier import Identifier
from core.responder import Responder

load_dotenv()

def main() -> None:
    identifier = Identifier()
    responder = Responder()

    while True:
        target = input("\nTarget: ").strip()

        if target.lower() == "q":
            print("Exiting.")
            break

        if not target:
            continue

        entity, result = identifier.process(target)

        print(f"\nType: {entity.type.value}")

        response = responder.respond(entity, result)

        print(f"\n{response}")

if __name__ == "__main__":
    main()