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

    VALID_STATUSES = {"success", "partial", "no_results", "error"}

    FIELD_MAP = {
        "geography": {
            "geography": {
                "registrant_location": "Registrant location",
                "published_locations": "Published locations",
                "geographic_locations": "Geographic locations",
            },
            "network": {
                "ip_addresses": "IP addresses",
                "ipv4_addresses": "IPv4 addresses",
                "ipv6_addresses": "IPv6 addresses",
                "ip_ranges": "IP ranges",
                "ip_ranges_cidr": "IP ranges",
                "network_locations": "Network locations",
            },
        },
        "network": {
            "network": {
                "network_owner": "Network owner",
                "network_owners": "Network owners",
                "isp": "Internet service provider",
                "isp_name": "Internet service provider",
                "hosting_provider": "Hosting provider",
                "hosting_providers": "Hosting providers",
                "autonomous_system_numbers": "Autonomous system numbers",
                "asn_organisation_names": "ASN organisations",
                "origin_asns": "Origin ASNs",
                "reverse_dns_hostnames": "Reverse DNS hostnames",
                "bgp_announced_prefixes": "BGP announced prefixes",
            },
        },
        "digital_identities": {
            "identity": {
                "registrant_name": "Registrant",
                "registrant_organisation": "Registrant organisation",
                "organisation_names": "Organisations",
                "company_names": "Companies",
                "published_individual_names": "Published individuals",
                "business_addresses": "Business addresses",
                "telephone_numbers": "Telephone numbers",
                "website_email_addresses": "Email addresses",
                "registrant_email_addresses": "Registrant email addresses",
                "contact_email_addresses": "Contact email addresses",
                "public_usernames": "Public usernames",
                "social_media_accounts": "Social media accounts",
            },
            "email": {
                "website_email_addresses": "Email addresses",
                "registrant_email_addresses": "Registrant email addresses",
                "administrative_contact": "Administrative contacts",
                "technical_contact_emails": "Technical contact emails",
                "abuse_contact_emails": "Abuse contact emails",
                "public_document_email": "Document email addresses",
                "email_addresses": "Email addresses",
                "emails": "Email addresses",
            },
            "website": {
                "company_names": "Companies",
                "organisation_names": "Organisations",
                "published_individual_names": "Published individuals",
                "business_addresses": "Business addresses",
                "telephone_numbers": "Telephone numbers",
                "contact_email_addresses": "Contact email addresses",
                "public_usernames": "Public usernames",
                "social_media_accounts": "Social media accounts",
            },
        },
        "infrastructure": {
            "hostname": {
                "subdomains": "Subdomains",
                "historical_subdomains": "Historical subdomains",
                "nameserver_hostnames": "Nameservers",
                "mail_server_hostnames": "Mail servers",
                "canonical_hostnames": "Canonical hostnames",
                "redirect_destinations": "Redirect destinations",
                "related_domains": "Related domains",
                "domains_sharing_ip": "Domains sharing IP addresses",
                "domains_sharing_nameservers": "Domains sharing nameservers",
                "domains_sharing_certificates": "Domains sharing certificates",
            },
            "email": {
                "mail_server_hostnames": "Mail servers",
                "email_service_providers": "Email service providers",
            },
        },
        "historical": {
            "history": {
                "previously_associated_ip_addresses": "Previously observed IP addresses",
                "previously_associated_nameservers": "Previously observed nameservers",
                "historical_subdomains": "Historical subdomains",
                "previous_registrant_organisations": "Previous registrant organisations",
                "previous_hosting_providers": "Previous hosting providers",
                "previously_observed_email_infrastructure": "Previous email infrastructure",
                "first_seen_date": "First observed",
                "last_seen_date": "Last observed",
            },
        },
        "technical": {
            "technical": {
                "technologies": "Technologies",
                "technology_identifiers": "Technology identifiers",
                "cms_identifiers": "CMS identifiers",
                "server_banners": "Server banners",
                "open_ports": "Open ports",
                "service_versions": "Service versions",
                "public_api_endpoints": "Public API endpoints",
                "favicon_hashes": "Favicon hashes",
                "http_response_hashes": "HTTP response hashes",
                "html_content_hashes": "HTML content hashes",
                "javascript_file_hashes": "JavaScript hashes",
                "tls_fingerprints": "TLS fingerprints",
            },
            "website": {
                "technologies": "Technologies",
                "technology_identifiers": "Technology identifiers",
                "cms_identifiers": "CMS identifiers",
                "analytics_ids": "Analytics identifiers",
                "advertising_ids": "Advertising identifiers",
                "payment_provider_ids": "Payment provider identifiers",
            },
        },
    }

    LEAD_FIELDS = {
        "ip": {
            "ip_addresses",
            "ipv4_addresses",
            "ipv6_addresses",
            "previously_associated_ip_addresses",
            "reported_malicious_ip_addresses",
        },
        "domain": {
            "registered_domain",
            "parent_domain",
            "related_domains",
            "domains_sharing_ip",
            "domains_sharing_nameservers",
            "domains_sharing_certificates",
        },
        "hostname": {
            "subdomains",
            "historical_subdomains",
            "nameserver_hostnames",
            "mail_server_hostnames",
            "canonical_hostnames",
            "reverse_dns_hostnames",
        },
        "email": {
            "website_email_addresses",
            "registrant_email_addresses",
            "contact_email_addresses",
            "technical_contact_emails",
            "abuse_contact_emails",
            "public_document_email",
            "email_addresses",
            "emails",
        },
        "url": {
            "urls",
            "redirect_destinations",
            "public_api_endpoints",
            "document_urls",
        },
        "organisation": {
            "company_names",
            "organisation_names",
            "registrant_organisation",
            "network_owner",
            "hosting_provider",
        },
        "person": {
            "registrant_name",
            "published_individual_names",
        },
        "username": {
            "public_usernames",
        },
        "phone": {
            "telephone_numbers",
        },
        "location": {
            "registrant_location",
            "published_locations",
            "geographic_locations",
            "business_addresses",
        },
    }

    IDENTIFICATION_FIELDS = {
        "identity": {
            "registrar_name": "Registrar",
            "registrar": "Registrar",
            "registered_domain": "Registered domain",
            "registrant_name": "Registrant",
            "registrant_organisation": "Registrant organisation",
            "registration_date": "Registration date",
            "creation_date": "Creation date",
            "expiration_date": "Expiration date",
            "updated_date": "Last updated",
        },
        "hostname": {
            "registered_domain": "Registered domain",
            "parent_domain": "Parent domain",
        },
    }

    @classmethod
    def _is_empty(cls, value):
        if value is None:
            return True

        if isinstance(value, str):
            return value.strip().casefold() in cls.EMPTY_VALUES

        if isinstance(value, (list, tuple, set)):
            return len(value) == 0 or all(cls._is_empty(item) for item in value)

        if isinstance(value, Mapping):
            return len(value) == 0 or all(
                cls._is_empty(item) for item in value.values()
            )

        return False

    @classmethod
    def _normalise_value(cls, value):
        if isinstance(value, Mapping):
            return {
                key: normalised
                for key, item in value.items()
                if not cls._is_empty(normalised := cls._normalise_value(item))
            }

        if isinstance(value, (list, tuple, set)):
            result = []

            for item in value:
                normalised = cls._normalise_value(item)

                if cls._is_empty(normalised):
                    continue

                if not any(cls._equivalent(normalised, existing) for existing in result):
                    result.append(normalised)

            return result

        if isinstance(value, str):
            value = value.strip()
            return None if cls._is_empty(value) else value

        return deepcopy(value)

    @staticmethod
    def _equivalent(first, second):
        try:
            return json.dumps(first, sort_keys=True, default=str) == json.dumps(
                second, sort_keys=True, default=str
            )
        except (TypeError, ValueError):
            return first == second

    @classmethod
    def _merge_values(cls, first, second):
        if cls._is_empty(first):
            return deepcopy(second)

        if cls._is_empty(second):
            return deepcopy(first)

        if isinstance(first, Mapping) and isinstance(second, Mapping):
            merged = deepcopy(first)

            for key, value in second.items():
                if key in merged:
                    merged[key] = cls._merge_values(merged[key], value)
                else:
                    merged[key] = deepcopy(value)

            return merged

        if isinstance(first, list) or isinstance(second, list):
            first_values = first if isinstance(first, list) else [first]
            second_values = second if isinstance(second, list) else [second]

            merged = deepcopy(first_values)

            for value in second_values:
                if not any(cls._equivalent(value, item) for item in merged):
                    merged.append(deepcopy(value))

            return merged

        if cls._equivalent(first, second):
            return deepcopy(first)

        return [deepcopy(first), deepcopy(second)]

    @classmethod
    def _normalise_status(cls, status):
        if not isinstance(status, str):
            return "error"

        status = status.strip().casefold()

        aliases = {
            "complete": "success",
            "completed": "success",
            "incomplete": "partial",
            "failed": "error",
            "failure": "error",
        }

        status = aliases.get(status, status)

        return status if status in cls.VALID_STATUSES else "error"

    @classmethod
    def _normalise_list(cls, value):
        if value is None:
            return []

        if not isinstance(value, list):
            value = [value]

        result = []

        for item in value:
            normalised = cls._normalise_value(item)

            if cls._is_empty(normalised):
                continue

            if not any(cls._equivalent(normalised, existing) for existing in result):
                result.append(normalised)

        return result

    @classmethod
    def _normalise_module(cls, module_name, envelope):
        if not isinstance(envelope, Mapping):
            envelope = {
                "status": "error",
                "data": {},
                "errors": ["Invalid module envelope."],
            }

        data = cls._normalise_value(envelope.get("data", {}))

        if not isinstance(data, Mapping):
            data = {"result": data}

        errors = cls._normalise_list(envelope.get("errors", []))

        if envelope.get("error"):
            errors = cls._normalise_list(errors + [envelope["error"]])

        status = cls._normalise_status(envelope.get("status", "error"))

        if errors and status in {"success", "no_results"}:
            status = "partial" if not cls._is_empty(data) else "error"

        return {
            "module": str(envelope.get("module") or module_name),
            "status": status,
            "data": data,
            "provenance": cls._normalise_list(envelope.get("provenance", [])),
            "related_entities": cls._normalise_list(
                envelope.get("related_entities", [])
            ),
            "errors": errors,
        }

    @classmethod
    def _merge_modules(cls, first, second):
        return {
            "module": first["module"],
            "status": cls._overall_status([first, second]),
            "data": cls._merge_values(first["data"], second["data"]),
            "provenance": cls._normalise_list(
                first["provenance"] + second["provenance"]
            ),
            "related_entities": cls._normalise_list(
                first["related_entities"] + second["related_entities"]
            ),
            "errors": cls._normalise_list(first["errors"] + second["errors"]),
        }

    @classmethod
    def _overall_status(cls, modules):
        if not modules:
            return "no_results"

        statuses = {module["status"] for module in modules}

        if statuses == {"success"}:
            return "success"

        if statuses <= {"success", "no_results"}:
            return "success" if "success" in statuses else "no_results"

        if statuses == {"no_results"}:
            return "no_results"

        if statuses == {"error"}:
            return "error"

        if "success" in statuses or "partial" in statuses:
            return "partial"

        return "error"

    @staticmethod
    def _display(value):
        if isinstance(value, Mapping):
            return value

        if isinstance(value, list):
            return value

        return value

    @classmethod
    def _iter_values(cls, value):
        if cls._is_empty(value):
            return

        if isinstance(value, Mapping):
            for item in value.values():
                yield from cls._iter_values(item)
            return

        if isinstance(value, (list, tuple, set)):
            for item in value:
                yield from cls._iter_values(item)
            return

        yield value

    @staticmethod
    def _normalise_key(value):
        return str(value).strip().casefold()

    @classmethod
    def _add_report_item(cls, collection, label, value, module, field):
        if cls._is_empty(value):
            return

        values = list(cls._iter_values(value))

        for item in values:
            if isinstance(item, (Mapping, list)):
                continue

            key = cls._normalise_key(item)

            existing = next(
                (
                    entry
                    for entry in collection
                    if cls._normalise_key(entry["value"]) == key
                ),
                None,
            )

            source = {
                "module": module,
                "field": field,
            }

            if existing:
                if source not in existing["sources"]:
                    existing["sources"].append(source)
                continue

            collection.append({
                "label": label,
                "value": item,
                "sources": [source],
            })

    @classmethod
    def _build_identification(cls, modules):
        identification = {}

        for module in modules:
            module_name = module["module"].casefold()
            fields = cls.IDENTIFICATION_FIELDS.get(module_name, {})
            data = module["data"]

            for field, label in fields.items():
                value = data.get(field)

                if cls._is_empty(value):
                    continue

                if label in identification:
                    identification[label] = cls._merge_values(
                        identification[label], value
                    )
                else:
                    identification[label] = deepcopy(value)

        return identification

    @classmethod
    def _build_findings(cls, modules):
        findings = {
            "geography": [],
            "network": [],
            "digital_identities": [],
            "infrastructure": [],
            "historical": [],
            "technical": [],
        }

        for module in modules:
            module_name = module["module"].casefold()
            data = module["data"]

            for category, module_maps in cls.FIELD_MAP.items():
                fields = module_maps.get(module_name, {})

                for field, label in fields.items():
                    if field not in data:
                        continue

                    cls._add_report_item(
                        findings[category],
                        label,
                        data[field],
                        module_name,
                        field,
                    )

        return {
            category: items
            for category, items in findings.items()
            if items
        }

    @classmethod
    def _build_leads(cls, modules):
        leads = []

        def add_lead(entity_type, value, module, field, basis, relationship=None):
            if cls._is_empty(value) or isinstance(value, (Mapping, list)):
                return

            value = str(value).strip()

            key = (entity_type.casefold(), value.casefold())

            existing = next(
                (
                    lead for lead in leads
                    if (lead["type"].casefold(), lead["value"].casefold()) == key
                ),
                None,
            )

            source = {
                "module": module,
                "field": field,
            }

            if existing:
                if source not in existing["sources"]:
                    existing["sources"].append(source)
                if relationship and relationship not in existing["relationships"]:
                    existing["relationships"].append(relationship)
                if basis not in existing["basis"]:
                    existing["basis"].append(basis)
                return

            leads.append({
                "type": entity_type,
                "value": value,
                "basis": [basis],
                "relationships": [relationship] if relationship else [],
                "sources": [source],
            })

        for module in modules:
            module_name = module["module"].casefold()
            data = module["data"]

            for entity in module["related_entities"]:
                if isinstance(entity, str):
                    add_lead(
                        "entity",
                        entity,
                        module_name,
                        "related_entities",
                        "explicit_relationship",
                    )
                    continue

                if not isinstance(entity, Mapping):
                    continue

                value = (
                    entity.get("value")
                    or entity.get("name")
                    or entity.get("entity")
                    or entity.get("address")
                )

                entity_type = (
                    entity.get("type")
                    or entity.get("entity_type")
                    or "entity"
                )

                relationship = (
                    entity.get("relationship")
                    or entity.get("relation")
                )

                add_lead(
                    str(entity_type),
                    value,
                    module_name,
                    "related_entities",
                    "explicit_relationship",
                    relationship,
                )

            for entity_type, fields in cls.LEAD_FIELDS.items():
                for field in fields:
                    if field not in data:
                        continue

                    for value in cls._iter_values(data[field]):
                        add_lead(
                            entity_type,
                            value,
                            module_name,
                            field,
                            "extracted_value",
                        )

        return leads

    @classmethod
    def _build_supporting_data(cls, modules):
        supporting = {}

        for module in modules:
            module_name = module["module"].casefold()
            data = module["data"]

            if module_name == "hostname":
                for field in (
                    "nameservers",
                    "nameserver_hostnames",
                    "mail_server_hostnames",
                    "cname_records",
                    "dns_records",
                ):
                    if field in data and not cls._is_empty(data[field]):
                        supporting[field] = cls._merge_values(
                            supporting.get(field), data[field]
                        )

            elif module_name == "crt":
                for field in (
                    "certificate_issuer",
                    "certificate_organisation",
                    "certificate_common_name",
                    "subject_alternative_names",
                    "certificate_records",
                    "certificates",
                ):
                    if field in data and not cls._is_empty(data[field]):
                        supporting[field] = cls._merge_values(
                            supporting.get(field), data[field]
                        )

        return supporting

    @classmethod
    def _build_report(cls, modules):
        return {
            "identification": cls._build_identification(modules),
            "findings": cls._build_findings(modules),
            "investigation_leads": cls._build_leads(modules),
            "supporting_data": cls._build_supporting_data(modules),
        }

    @classmethod
    def respond(cls, response):
        if not isinstance(response, Mapping):
            raise TypeError("Responder expects a mapping.")

        domain = response.get("domain")

        if not isinstance(domain, str) or not domain.strip():
            raise ValueError("Response must contain a valid domain.")

        raw_modules = response.get("modules", {})

        if isinstance(raw_modules, Mapping):
            module_items = raw_modules.items()
        elif isinstance(raw_modules, list):
            module_items = [
                (item.get("module", f"module_{index}"), item)
                if isinstance(item, Mapping)
                else (f"module_{index}", item)
                for index, item in enumerate(raw_modules)
            ]
        else:
            raise TypeError("Response modules must be a mapping or list.")

        consolidated = {}

        for module_name, envelope in module_items:
            module = cls._normalise_module(module_name, envelope)
            key = module["module"].casefold()

            if key in consolidated:
                consolidated[key] = cls._merge_modules(
                    consolidated[key],
                    module,
                )
            else:
                consolidated[key] = module

        modules = list(consolidated.values())

        return {
            "domain": domain.strip().lower(),
            "status": cls._overall_status(modules),
            "report": cls._build_report(modules),
            "modules": modules,
        }

def respond(response):
    return Responder.respond(response)