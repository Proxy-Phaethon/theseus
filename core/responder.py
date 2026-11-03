import json
from collections.abc import Mapping
from copy import deepcopy

class Responder:

    EMPTY_VALUES = {
        "",
        "none",
        "null",
        "n/a",
        "na",
        "not available",
        "not found",
    }

    VALID_STATUSES = {
        "success",
        "partial",
        "no_results",
        "error",
    }

    @staticmethod
    def _is_empty(value) -> bool:
        if value is None:
            return True

        if isinstance(value, str):
            return value.strip().lower() in Responder.EMPTY_VALUES

        return False

    @classmethod
    def _normalise_value(cls, value):
        if cls._is_empty(value):
            return None

        if isinstance(value, Mapping):
            return {
                str(key): cls._normalise_value(item)
                for key, item in value.items()
            }

        if isinstance(value, (list, tuple, set)):
            result = []

            for item in value:
                normalised = cls._normalise_value(item)

                if not any(
                    cls._equivalent(normalised, existing)
                    for existing in result
                ):
                    result.append(normalised)

            return result

        return value

    @staticmethod
    def _equivalent(first, second) -> bool:
        try:
            return json.dumps(
                first,
                sort_keys=True,
                default=str,
            ) == json.dumps(
                second,
                sort_keys=True,
                default=str,
            )
        except (TypeError, ValueError):
            return first == second

    @classmethod
    def _merge_values(cls, existing, incoming):
        if existing is None:
            return deepcopy(incoming)

        if incoming is None:
            return deepcopy(existing)

        if isinstance(existing, dict) and isinstance(incoming, dict):
            merged = deepcopy(existing)

            for key, value in incoming.items():
                if key in merged:
                    merged[key] = cls._merge_values(
                        merged[key],
                        value,
                    )
                else:
                    merged[key] = deepcopy(value)

            return merged

        if isinstance(existing, list) and isinstance(incoming, list):
            return cls._normalise_value(existing + incoming)

        if cls._equivalent(existing, incoming):
            return deepcopy(existing)

        return cls._normalise_value([existing, incoming])

    @classmethod
    def _normalise_status(cls, status) -> str:
        status = str(status or "").strip().lower()

        aliases = {
            "complete": "success",
            "completed": "success",
            "incomplete": "partial",
            "failed": "error",
            "failure": "error",
        }

        status = aliases.get(status, status)

        if status not in cls.VALID_STATUSES:
            return "error"

        return status

    @classmethod
    def _normalise_list(cls, value) -> list:
        if value is None:
            return []

        if isinstance(value, (list, tuple, set)):
            items = value
        else:
            items = [value]

        result = []

        for item in items:
            normalised = cls._normalise_value(item)

            if not any(
                cls._equivalent(normalised, existing)
                for existing in result
            ):
                result.append(normalised)

        return result

    @classmethod
    def _normalise_module(
        cls,
        envelope: dict,
        fallback_name: str = "unknown",
    ) -> dict:

        module = str(
            envelope.get("module") or fallback_name
        ).strip().lower()

        raw_data = envelope.get("data", {})

        if not isinstance(raw_data, Mapping):
            raw_data = {"result": raw_data}

        data = {
            str(key): cls._normalise_value(value)
            for key, value in raw_data.items()
        }

        provenance = cls._normalise_list(
            envelope.get("provenance")
        )

        related_entities = cls._normalise_list(
            envelope.get("related_entities")
        )

        errors = cls._normalise_list(
            envelope.get("errors")
        )

        if envelope.get("error"):
            errors = cls._normalise_list(
                errors + [envelope["error"]]
            )

        status = cls._normalise_status(
            envelope.get("status")
        )

        if errors and status == "success":
            status = "partial"

        if errors and status == "no_results":
            status = "error"

        return {
            "module": module,
            "status": status,
            "data": data,
            "provenance": provenance,
            "related_entities": related_entities,
            "errors": errors,
        }

    @classmethod
    def _merge_modules(
        cls,
        existing: dict,
        incoming: dict,
    ) -> dict:

        merged = deepcopy(existing)

        for key, value in incoming["data"].items():
            if key in merged["data"]:
                merged["data"][key] = cls._merge_values(
                    merged["data"][key],
                    value,
                )
            else:
                merged["data"][key] = deepcopy(value)

        merged["provenance"] = cls._normalise_list(
            merged["provenance"] + incoming["provenance"]
        )

        merged["related_entities"] = cls._normalise_list(
            merged["related_entities"]
            + incoming["related_entities"]
        )

        merged["errors"] = cls._normalise_list(
            merged["errors"] + incoming["errors"]
        )

        statuses = {
            merged["status"],
            incoming["status"],
        }

        if "partial" in statuses:
            merged["status"] = "partial"
        elif "error" in statuses:
            merged["status"] = "partial"
        elif "success" in statuses:
            merged["status"] = "success"
        else:
            merged["status"] = "no_results"

        return merged

    @classmethod
    def _overall_status(cls, modules: list) -> str:
        if not modules:
            return "no_results"

        statuses = [module["status"] for module in modules]

        if all(status == "no_results" for status in statuses):
            return "no_results"

        if all(status == "error" for status in statuses):
            return "error"

        if "partial" in statuses or "error" in statuses:
            return "partial"

        return "success"

    @classmethod
    def respond(cls, response: dict) -> dict:
        if not isinstance(response, dict):
            raise TypeError(
                "Responder expected a dictionary."
            )

        domain = response.get("domain")

        if not isinstance(domain, str) or not domain.strip():
            raise ValueError(
                "Response is missing a valid domain."
            )

        raw_modules = response.get("modules", [])

        if isinstance(raw_modules, Mapping):
            module_items = list(raw_modules.items())
        elif isinstance(raw_modules, list):
            module_items = [
                (None, envelope)
                for envelope in raw_modules
            ]
        else:
            module_items = []

        consolidated = {}

        for index, (fallback_name, envelope) in enumerate(
            module_items,
            start=1,
        ):
            if not isinstance(envelope, dict):
                envelope = {
                    "module": fallback_name or f"unknown_{index}",
                    "status": "error",
                    "data": {},
                    "provenance": [],
                    "related_entities": [],
                    "errors": [
                        "Invalid module response envelope."
                    ],
                }

            module_result = cls._normalise_module(
                envelope,
                fallback_name=fallback_name or f"unknown_{index}",
            )

            module_name = module_result["module"]

            if module_name in consolidated:
                consolidated[module_name] = cls._merge_modules(
                    consolidated[module_name],
                    module_result,
                )
            else:
                consolidated[module_name] = module_result

        modules = list(consolidated.values())

        return {
            "domain": domain.strip().lower(),
            "status": cls._overall_status(modules),
            "modules": modules,
        }

def respond(response: dict) -> dict:
    return Responder.respond(response)