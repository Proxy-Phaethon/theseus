import httpx
import trio
import warnings

from holehe.core import get_functions, import_submodules, launch_module

class HoleheTool:
    async def _run(self, email):
        modules = import_submodules("holehe.modules")
        websites = get_functions(modules)

        results = []
        client = httpx.AsyncClient(timeout=10)

        try:
            with warnings.catch_warnings():
                warnings.filterwarnings(
                    "ignore",
                    message=(
                        r"Some characters could not be decoded, "
                        r"and were replaced with REPLACEMENT CHARACTER\."
                    ),
                    category=UnicodeWarning,
                )

                async with trio.open_nursery() as nursery:
                    for website in websites:
                        nursery.start_soon(
                            launch_module,
                            website,
                            email,
                            client,
                            results,
                        )
        finally:
            await client.aclose()

        return sorted(results, key=lambda item: item["name"])

    def run(self, email):
        email = email.strip()

        return trio.run(self._run, email)