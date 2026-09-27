from __future__ import annotations

from typing import Any

from core.identifier import Entity, EntityType

class Responder:
    def respond(self, entity: Entity, result: Any) -> str:
        formatters = {
            EntityType.IP_ADDRESS: self._format_ip,
            EntityType.DOMAIN: self._format_domain,
            EntityType.EMAIL: self._format_email,
            EntityType.USERNAME: self._format_username,
            EntityType.URL: self._format_url,
            EntityType.PHONE: self._format_phone,
            EntityType.PERSON: self._format_person,
            EntityType.ORGANIZATION: self._format_organization,
        }

        formatter = formatters.get(
            entity.type,
            self._format_unknown,
        )

        return formatter(entity, result)

    def _format_ip(
        self,
        entity: Entity,
        result: Any,
    ) -> str:
        ...

    def _format_domain(
        self,
        entity: Entity,
        result: Any,
    ) -> str:
        ...

    def _format_email(
        self,
        entity: Entity,
        result: Any,
    ) -> str:
        ...

    def _format_username(
        self,
        entity: Entity,
        result: Any,
    ) -> str:
        ...

    def _format_url(
        self,
        entity: Entity,
        result: Any,
    ) -> str:
        ...

    def _format_phone(
        self,
        entity: Entity,
        result: Any,
    ) -> str:
        ...

    def _format_person(
        self,
        entity: Entity,
        result: Any,
    ) -> str:
        ...

    def _format_organization(
        self,
        entity: Entity,
        result: Any,
    ) -> str:
        ...

    def _format_unknown(
        self,
        entity: Entity,
        result: Any,
    ) -> str:
        ...