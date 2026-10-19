import logging

import httpx
import trio

from holehe.core import get_functions, import_submodules, launch_module

class HoleheTool:
    async def _run(self, email):
        modules = import_submodules("holehe.modules")
        websites = get_functions(modules)

        results = []
        client = httpx.AsyncClient(timeout=10)

        warning_message = (
            "Some characters could not be decoded, and were "
            "replaced with REPLACEMENT CHARACTER."
        )

        class DecodeWarningFilter(logging.Filter):
            def filter(self, record):
                return record.getMessage() != warning_message

        root_logger = logging.getLogger()
        warning_filter = DecodeWarningFilter()
        root_logger.addFilter(warning_filter)

        try:
            async with client:
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
            root_logger.removeFilter(warning_filter)

        return sorted(results, key=lambda item: item["name"])

    def run(self, email):
        email = email.strip()
        return trio.run(self._run, email)