from core.identifier import Identifier
from core.domain import process as process_domain

from ui.shell import TheseusShell
from ui.banner import VERSION

def process_input(value: str) -> dict:
    identification = Identifier.identify(value)

    if not identification.get("success"):
        raise ValueError(
            identification.get(
                "error",
                "Input could not be identified."
            )
        )

    return process_domain(identification)

def main() -> None:
    shell = TheseusShell(
        processor=process_input,
        version=VERSION,
    )

    shell.run()

if __name__ == "__main__":
    main()