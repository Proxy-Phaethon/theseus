import requests

RDAP_ENDPOINT = "https://rdap.org/domain/{}"

TIMEOUT = 15

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

def empty_data():
    return {field: "none" for field in FIELDS}

def get_vcard(entity):
    result = {}

    vcard = entity.get("vcardArray", [])

    if len(vcard) < 2:
        return result

    for item in vcard[1]:

        if len(item) < 4:
            continue

        name = item[0].lower()
        value = item[3]

        if name == "adr" and isinstance(value, list):
            result[name] = [
                str(part) for part in value if part
            ]

        elif isinstance(value, str):
            result[name] = value

    return result

def get_contact(entity):
    vcard = get_vcard(entity)

    address = vcard.get("adr", [])

    return {
        "name": vcard.get("fn", "none"),
        "organisation": vcard.get("org", "none"),
        "email": vcard.get("email", "none"),
        "telephone": vcard.get("tel", "none"),
        "address": ", ".join(address) if address else "none"
    }

def find_entities(entities, role):
    matches = []

    for entity in entities:

        roles = [
            item.lower()
            for item in entity.get("roles", [])
        ]

        if role in roles:
            matches.append(entity)

    return matches

def get_registrant_location(entity):
    vcard = get_vcard(entity)
    address = vcard.get("adr", [])

    location = {
        "country": "none",
        "state_region": "none",
        "city": "none",
        "postal_address": "none"
    }

    if len(address) >= 7:

        location["postal_address"] = ", ".join(
            str(part) for part in address if part
        ) or "none"

        location["city"] = address[3] or "none"
        location["state_region"] = address[4] or "none"
        location["country"] = address[6] or "none"

    return location

def run(domain: str) -> dict:
    data = empty_data()
    provenance = []
    related_entities = []

    try:

        response = requests.get(
            RDAP_ENDPOINT.format(domain),
            headers={"Accept": "application/rdap+json"},
            timeout=TIMEOUT
        )

        response.raise_for_status()

        rdap = response.json()

        provenance.append({
            "source": "RDAP",
            "url": response.url
        })

        entities = rdap.get("entities", [])

        registrants = find_entities(entities, "registrant")

        if registrants:

            registrant = registrants[0]
            contact = get_contact(registrant)
            location = get_registrant_location(registrant)

            data["registrant_name"] = contact["name"]
            data["registrant_organisation"] = contact["organisation"]
            data["registrant_email"] = contact["email"]
            data["registrant_telephone"] = contact["telephone"]

            data["registrant_country"] = location["country"]
            data["registrant_state_region"] = location["state_region"]
            data["registrant_city"] = location["city"]
            data["registrant_postal_address"] = location["postal_address"]

            if contact["organisation"] != "none":
                related_entities.append({
                    "type": "organisation",
                    "name": contact["organisation"],
                    "relationship": "domain registrant"
                })

        registrars = find_entities(entities, "registrar")

        if registrars:
            data["registrar_name"] = get_contact(
                registrars[0]
            )["name"]

        administrative = find_entities(
            entities, "administrative"
        )

        if administrative:
            data["administrative_contact"] = get_contact(
                administrative[0]
            )

        technical = find_entities(
            entities, "technical"
        )

        if technical:
            data["technical_contact"] = get_contact(
                technical[0]
            )

        abuse = find_entities(entities, "abuse")

        if abuse:
            data["abuse_contact"] = get_contact(
                abuse[0]
            )

        missing = [
            field for field, value in data.items()
            if value == "none"
        ]

        status = "partial" if missing else "success"

        return {
            "status": status,
            "module": "identity",
            "data": data,
            "provenance": provenance,
            "related_entities": related_entities
        }

    except requests.RequestException as exc:

        return {
            "status": "error",
            "module": "identity",
            "data": data,
            "provenance": provenance,
            "related_entities": related_entities,
            "error": str(exc)
        }

    except (ValueError, KeyError, TypeError) as exc:

        return {
            "status": "error",
            "module": "identity",
            "data": data,
            "provenance": provenance,
            "related_entities": related_entities,
            "error": str(exc)
        }