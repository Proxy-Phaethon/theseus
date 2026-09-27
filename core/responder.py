from __future__ import annotations

import json
from typing import Any

class Responder:
    def respond(self, result: Any) -> str:
        if result is None:
            return "No result."

        if isinstance(result, str):
            return result

        if isinstance(result, (dict, list)):
            return json.dumps(
                result,
                indent=2,
                ensure_ascii=False,
            )

        return str(result)