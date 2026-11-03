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

    STATUS_PRIORITY = {
        "SUCCESS": 0,
        "PARTIAL": 1,
        "FAILED": 2,
    }

    @staticmethod
    def _is_empty(value) -> bool:

        if value is None:
            return True

        if isinstance(value, str):
            return value.strip().lower() in Responder.EMPTY_VALUES

        if isinstance(value, (list, tuple, set, dict)):
            return len(value) == 0

        return False

    @classmethod
    def _normalise_value(cls, value):

        if cls._is_empty(value):
            return None

        if isinstance(value, dict):
            result = {
                key: cls._normalise_value(item)
                for key, item in value.items()
            }

            if all(item is None for item in result.values()):
                return None

            return result

        if isinstance(value, (list, tuple, set)):
            result = []

            for item in value:
                normalised = cls._normalise_value(item)

                if normalised is None:
                    continue

                if not any(
                    cls._equivalent(normalised, existing)
                    for existing in result
                ):
                    result.append(normalised)

            return result or None

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
    def _normalise_status(cls, status: str) -> str:
        status = str(status or "").strip().upper()

        if status in {"SUCCESS", "COMPLETE", "COMPLETED"}:
            return "SUCCESS"

        if status in {"PARTIAL", "INCOMPLETE"}:
            return "PARTIAL"

        if status in {"FAILED", "FAILURE", "ERROR"}:
            return "FAILED"

        return "PARTIAL"

    @classmethod
    def _combine_statuses(cls, statuses: list[str]) -> str:
        if not statuses:
            return "PARTIAL"

        return max(
            statuses,
            key=lambda status: cls.STATUS_PRIORITY[status],
        )

    @classmethod
    def _normalise_list(cls, value) -> list:
        if value is None:
            return []

        if not isinstance(value, list):
            value = [value]

        result = []

        for item in value:
            normalised = cls._normalise_value(item)

            if normalised is None:
                continue

            if not any(
                cls._equivalent(normalised, existing)
                for existing in result
            ):
                result.append(normalised)

        return result

    @classmethod
    def _normalise_module(cls, envelope: dict) -> dict:
        module = str(envelope.get("module") or "unknown").strip()

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

        if errors and status == "SUCCESS":
            status = "PARTIAL"

        result = {
            "module": module,
            "status": status,
            "data": data,
            "provenance": provenance,
            "related_entities": related_entities,
        }

        if errors:
            result["errors"] = errors

        return result

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

        merged["status"] = cls._combine_statuses([
            merged["status"],
            incoming["status"],
        ])

        merged["errors"] = cls._normalise_list(
            merged.get("errors", [])
            + incoming.get("errors", [])
        )

        if not merged["errors"]:
            merged.pop("errors", None)

        return merged

    @classmethod
    def respond(cls, response: dict) -> dict:
        if not isinstance(response, dict):
            raise TypeError("Responder expected a dictionary.")

        domain = response.get("domain")

        if not isinstance(domain, str) or not domain.strip():
            raise ValueError("Response is missing a valid domain.")

        raw_modules = response.get("modules", [])

        if not isinstance(raw_modules, list):
            raw_modules = []

        consolidated = {}

        for index, envelope in enumerate(raw_modules):
            if not isinstance(envelope, dict):
                envelope = {
                    "module": f"unknown_{index + 1}",
                    "status": "FAILED",
                    "data": {},
                    "error": "Invalid module response envelope.",
                }

            module_result = cls._normalise_module(envelope)
            module_name = module_result["module"].lower()

            if module_name in consolidated:
                consolidated[module_name] = cls._merge_modules(
                    consolidated[module_name],
                    module_result,
                )
            else:
                consolidated[module_name] = module_result

        modules = list(consolidated.values())

        overall_status = cls._combine_statuses([
            module["status"] for module in modules
        ])

        return {
            "domain": domain.strip().lower(),
            "status": overall_status,
            "modules": modules,
        }

def respond(response: dict) -> dict:
    return Responder.respond(response)