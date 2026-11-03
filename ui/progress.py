from contextlib import contextmanager
from typing import Iterator

from rich.status import Status

from ui.terminal import (
    ANIMATION_ENABLED,
    console,
)

@contextmanager
def extraction_progress(
    message: str = "EXTRACTING ARTEFACT INFORMATION...",
) -> Iterator[None]:

    if ANIMATION_ENABLED:
        with console.status(
            message,
            spinner="dots",
            spinner_style="accent",
            speed=0.8,
        ):
            yield

    else:
        console.print(f"[*] {message}", style="accent")
        yield

@contextmanager
def operation_progress(
    message: str = "PROCESSING...",
) -> Iterator[None]:

    if ANIMATION_ENABLED:
        with console.status(
            message,
            spinner="dots",
            spinner_style="accent",
        ):
            yield

    else:
        console.print(f"[*] {message}", style="accent")
        yield