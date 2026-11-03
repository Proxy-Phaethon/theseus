import requests

from datetime import datetime, timezone

MODULE_NAME = "identity"

RDAP_ENDPOINT = "https://rdap.org/domain/{}"

TIMEOUT = 15

HEADERS = {
    "Accept": "application/rdap+json",
    "User-Agent": "Theseus/1.0"
}

FIELDS = (
    "registrant_name",
    "registrant_organisation",
    "registrar_name",
    "registrant_country",
    "registrant_state_region",
    "registrant_city",
    "registrant_postal_address",
    "registrant_email",
    "registrant_telephone",
    "administrative_contact",
    "technical_contact",
    "abuse_contact",
    "associated_legal_entity",
    "parent_organisation"
)

def empty_data() -> dict:
    return {
        "registrant_name": None,
        "registrant_organisation": None,
        "registrar_name": None,
        "registrant_country": None,
        "registrant_state_region": None,
        "registrant_city": None,
        "registrant_postal_address": None,
        "registrant_email": None,
        "registrant_telephone": None,
        "administrative_contact": None,
        "technical_contact": None,
        "abuse_contact": None,
        "associated_legal_entity": None,
        "parent_organisation": None
    }

def make_envelope(
    status: str,
    data: dict = None,
    provenance: list = None,
    related_entities: list = None,
    errors: list = None
) -> dict:
    return {
        "module": MODULE_NAME,
        "status": status,
        "data": data if data is not None else empty_data(),
        "provenance": provenance if provenance is not None else [],
        "related_entities": (
            related_entities if related_entities is not None else []
        ),
        "errors": errors if errors is not None else []
    }

def get_vcard(entity: dict) -> dict:
    result = {}

    vcard = entity.get("vcardArray", [])

    if (
        not isinstance(vcard, list)
        or len(vcard) < 2
        or not isinstance(vcard[1], list)
    ):
        return result

    for item in vcard[1]:
        if not isinstance(item, list) or len(item) < 4:
            continue

        name = str(item[0]).lower()
        value = item[3]

        if name == "adr" and isinstance(value, list):
            result[name] = [
                str(part).strip()
                for part in value
                if part
            ]

        elif isinstance(value, str):
            result[name] = value.strip()

        elif isinstance(value, list):
            result[name] = value

    return result

def get_contact(entity: dict) -> dict:
    vcard = get_vcard(entity)

    address = vcard.get("adr", [])

    return {
        "name": vcard.get("fn"),
        "organisation": vcard.get("org"),
        "email": vcard.get("email"),
        "telephone": vcard.get("tel"),
        "address": ", ".join(address) if address else None
    }

def find_entities(entities: list, role: str) -> list:
    matches = []

    for entity in entities:
        if not isinstance(entity, dict):
            continue

        roles = [
            str(item).lower()
            for item in entity.get("roles", [])
        ]

        if role.lower() in roles:
            matches.append(entity)

    return matches

def get_registrant_location(entity: dict) -> dict:
    vcard = get_vcard(entity)
    address = vcard.get("adr", [])

    location = {
        "country": None,
        "state_region": None,
        "city": None,
        "postal_address": None
    }

    if len(address) >= 7:
        location["postal_address"] = ", ".join(
            str(part)
            for part in address
            if part
        ) or None

        location["city"] = address[3] or None
        location["state_region"] = address[4] or None
        location["country"] = address[6] or None

    return location

def get_legal_entity(rdap: dict):
    entities = rdap.get("entities", [])

    for entity in entities:
        if not isinstance(entity, dict):
            continue

        roles = [
            str(role).lower()
            for role in entity.get("roles", [])
        ]

        if "legal" in roles:
            contact = get_contact(entity)

            return (
                contact["organisation"]
                or contact["name"]
            )

    return None

def get_parent_organisation(rdap: dict):
    entities = rdap.get("entities", [])

    for entity in entities:
        if not isinstance(entity, dict):
            continue

        roles = [
            str(role).lower()
            for role in entity.get("roles", [])
        ]

        if "parent" in roles:
            contact = get_contact(entity)

            return (
                contact["organisation"]
                or contact["name"]
            )

    return None

def add_related_entity(
    related_entities: list,
    entity_type: str,
    value: str,
    relationship: str
):
    if not value:
        return

    related_entities.append({
        "type": entity_type,
        "value": value,
        "relationship": relationship
    })

def run(domain: str) -> dict:
    data = empty_data()
    provenance = []
    related_entities = []
    errors = []

    try:
        response = requests.get(
            RDAP_ENDPOINT.format(domain),
            headers=HEADERS,
            timeout=TIMEOUT
        )

        response.raise_for_status()

        rdap = response.json()

        if not isinstance(rdap, dict):
            raise ValueError(
                "RDAP returned an unexpected response."
            )

        provenance.append({
            "source": "RDAP",
            "method": "Domain registration data retrieval",
            "retrieved_at": datetime.now(
                timezone.utc
            ).isoformat()
        })

        entities = rdap.get("entities", [])

        if not isinstance(entities, list):
            raise ValueError(
                "RDAP returned an invalid entity collection."
            )

        registrants = find_entities(
            entities,
            "registrant"
        )

        if registrants:
            registrant = registrants[0]

            contact = get_contact(registrant)
            location = get_registrant_location(registrant)

            data["registrant_name"] = contact["name"]
            data["registrant_organisation"] = (
                contact["organisation"]
            )
            data["registrant_email"] = contact["email"]
            data["registrant_telephone"] = contact["telephone"]

            data["registrant_country"] = location["country"]
            data["registrant_state_region"] = (
                location["state_region"]
            )
            data["registrant_city"] = location["city"]
            data["registrant_postal_address"] = (
                location["postal_address"]
            )

            add_related_entity(
                related_entities,
                "organisation",
                contact["organisation"],
                "domain_registrant"
            )

        registrars = find_entities(
            entities,
            "registrar"
        )

        if registrars:
            registrar_contact = get_contact(
                registrars[0]
            )

            data["registrar_name"] = (
                registrar_contact["name"]
                or registrar_contact["organisation"]
            )

        administrative = find_entities(
            entities,
            "administrative"
        )

        if administrative:
            data["administrative_contact"] = get_contact(
                administrative[0]
            )

        technical = find_entities(
            entities,
            "technical"
        )

        if technical:
            data["technical_contact"] = get_contact(
                technical[0]
            )

        abuse = find_entities(
            entities,
            "abuse"
        )

        if abuse:
            data["abuse_contact"] = get_contact(
                abuse[0]
            )

        data["associated_legal_entity"] = get_legal_entity(
            rdap
        )

        data["parent_organisation"] = get_parent_organisation(
            rdap
        )

        add_related_entity(
            related_entities,
            "organisation",
            data["associated_legal_entity"],
            "associated_legal_entity"
        )

        add_related_entity(
            related_entities,
            "organisation",
            data["parent_organisation"],
            "parent_organisation"
        )

        seen = set()
        unique_entities = []

        for entity in related_entities:
            key = (
                entity["type"],
                entity["value"].lower(),
                entity["relationship"]
            )

            if key not in seen:
                seen.add(key)
                unique_entities.append(entity)

        related_entities = unique_entities

        populated_fields = any(
            value is not None and value != []
            for value in data.values()
        )

        status = (
            "success"
            if populated_fields
            else "no_results"
        )

        return make_envelope(
            status=status,
            data=data,
            provenance=provenance,
            related_entities=related_entities,
            errors=errors
        )

    except requests.RequestException as exc:
        errors.append(
            f"RDAP retrieval failed: {exc}"
        )

    except (ValueError, KeyError, TypeError) as exc:
        errors.append(
            f"RDAP response processing failed: {exc}"
        )

    except Exception as exc:
        errors.append(
            f"Unexpected identity extraction error: {exc}"
        )

    return make_envelope(
        status="error",
        data=data,
        provenance=provenance,
        related_entities=related_entities,
        errors=errors
    )