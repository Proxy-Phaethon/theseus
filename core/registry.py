"""Catalogue, discovery and capability registry for Theseus extractors."""

from __future__ import annotations

import importlib
from typing import Any

# The authoritative inventory of extractor modules.
# Paths are relative to the project root and use Python import notation.
EXTRACTOR_MODULES: dict[str, tuple[str, ...]] = {
    "webandbrowser": (
        "url", "http", "http_headers", "html_source", "javascript", "css",
        "web_metadata", "web_manifest", "robots_sitemap", "redirects",
        "cookies", "web_storage", "browser_history", "browser_bookmarks",
        "browser_downloads", "browser_profiles", "browser_extensions",
        "browser_credentials", "web_archives", "web_exposure", "favicons",
    ),
    "emailandmessages": (
        "email", "email_message", "email_headers", "email_authentication",
        "email_attachments", "email_delivery", "mailing_lists", "calendar",
        "contacts", "sms_mms", "chat_exports", "voicemail", "call_records",
        "sip", "message_notifications",
    ),
    "networkandinfrastructure": (
        "dns", "domain", "ip", "whois_rdap", "certificates",
        "certificate_transparency", "asn_bgp", "reverse_ip", "passive_dns",
        "internet_scan", "service_banners", "ssh_keys", "rir_records",
        "threat_indicators", "network_device_configs",
    ),
    "filesanddocuments": (
        "file_metadata", "file_signatures", "file_hashes", "exif", "pdf",
        "office_documents", "csv", "archives", "shortcuts_symlinks",
        "alternate_streams", "thumbnails", "ocr", "audio_video_metadata",
        "digital_signatures", "fonts", "executables", "debug_symbols",
        "deleted_file_remnants",
    ),
    "operating_systems": (
        "windows_registry", "windows_event_logs", "windows_prefetch",
        "windows_amcache", "windows_shimcache", "windows_userassist",
        "windows_jump_lists", "windows_lnk", "windows_shellbags",
        "windows_recycle_bin", "windows_srum", "windows_tasks_services",
        "windows_wmi", "windows_powershell", "windows_rdp",
        "windows_usb_pnp", "windows_defender_firewall", "windows_vss",
        "macos_logs", "macos_plists", "macos_fsevents", "macos_spotlight",
        "macos_quarantine", "macos_launch_items", "macos_tcc",
        "macos_keychain", "macos_snapshots", "linux_logs", "shell_history",
        "ssh_config", "scheduled_jobs", "package_history",
        "user_group_records", "host_network_config", "process_services",
        "audit_logs",
    ),
    "networktraffic": (
        "pcap", "network_flows", "dns_traffic", "tls_traffic",
        "http_traffic", "dhcp", "arp", "routing_tables", "vpn",
        "proxy_logs", "firewall_logs", "wifi", "bluetooth",
        "protocol_parsers",
    ),
    "identityandsecrets": (
        "jwt", "api_keys", "private_keys", "public_keys", "oauth_oidc",
        "environment_files", "cloud_credentials", "git_credentials",
        "password_hashes", "password_manager", "windows_credentials",
        "kerberos", "authentication_logs", "mfa_recovery", "reset_links",
        "client_certificates", "secret_scanning",
    ),
    "socialandpublicrecords": (
        "social_profiles", "social_posts", "social_connections",
        "social_media", "social_links", "username_discovery", "gravatar",
        "repository_profiles", "account_exports", "public_web_mentions",
    ),
    "mobile": (
        "mobile_sms", "mobile_contacts", "mobile_calls", "android_manifests",
        "ios_metadata", "mobile_app_data", "mobile_cache",
        "mobile_locations", "mobile_media", "mobile_notifications",
        "mobile_backups", "installed_apps", "mobile_connectivity",
        "device_identifiers", "mobile_chat",
    ),
    "softwareanddevelopment": (
        "git", "git_history", "git_config", "dependency_manifests",
        "lockfiles", "ci_cd", "infrastructure_as_code", "containers",
        "kubernetes", "build_logs", "sbom", "application_logs", "api_specs",
        "source_comments", "binary_strings", "dependency_vulnerabilities",
    ),
    "databasesandstructureddata": (
        "sqlite", "csv_data", "json_data", "jsonl_data", "xml_data",
        "yaml_data", "sql_dumps", "spreadsheet_data", "graph_databases",
        "api_archives", "search_indexes", "queues_events",
    ),
    "cloudandenterprise": (
        "cloud_audit_logs", "cloud_assets", "object_storage",
        "access_policies", "identity_providers", "directory_services",
        "saas_audit", "container_registries", "cloud_resources",
        "backup_catalogues", "status_pages", "enterprise_api_specs",
    ),
    "businessandpublicrecords": (
        "corporate_filings", "annual_reports", "securities_filings",
        "patents", "trademarks", "court_records", "procurement",
        "licences_permits", "job_advertisements", "press_releases",
        "academic_publications", "public_datasets", "public_advertising",
        "website_footers",
    ),
    "geospatialandmedia": (
        "gps", "gpx", "kml_kmz", "geojson", "shapefiles", "map_urls",
        "geotagged_posts", "subtitles", "transcription",
        "perceptual_hashes", "media_thumbnails",
    ),
}

class RegistryError(RuntimeError):
    """Raised for invalid extractor registration or registry operations."""

class ExtractorRegistry:
    """Discover extractor modules and index instances by capability.

    Each extractor instance must provide:
        name: str
        supported_artefact_types: iterable[str]
        execute(packet) -> Packet

    A module can expose either:
        EXTRACTOR = extractor_instance
        EXTRACTORS = [extractor_instance, ...]
        register_extractors(registry)
    """

    def __init__(self) -> None:
        self._extractors: dict[str, Any] = {}
        self._modules: dict[str, dict[str, Any]] = {}

    @staticmethod
    def _module_path(category: str, module_name: str) -> str:
        return f"extractors.{category}.{module_name}"

    def register(self, extractor: Any) -> None:
        """Register an extractor instance under its declared capabilities."""
        if extractor is None:
            raise RegistryError("Cannot register a None extractor.")

        name = getattr(extractor, "name", None)
        if not isinstance(name, str) or not name.strip():
            raise RegistryError(
                "An extractor must define a non-empty string 'name'."
            )

        name = name.strip()
        if name in self._extractors:
            raise RegistryError(
                f"An extractor named '{name}' is already registered."
            )

        declared_types = getattr(
            extractor, "supported_artefact_types", None
        )

        if declared_types is None or isinstance(declared_types, str):
            raise RegistryError(
                f"Extractor '{name}' must define "
                "'supported_artefact_types' as an iterable of strings."
            )

        try:
            declared_types = tuple(declared_types)
        except TypeError as exc:
            raise RegistryError(
                f"Invalid capabilities declared by '{name}'."
            ) from exc

        if not declared_types or any(
            not isinstance(item, str) or not item.strip()
            for item in declared_types
        ):
            raise RegistryError(
                f"Extractor '{name}' must declare valid artefact types."
            )

        if not callable(getattr(extractor, "execute", None)):
            raise RegistryError(
                f"Extractor '{name}' must implement execute(packet)."
            )

        # Normalise capability names once, during registration.
        normalised_types = tuple(
            dict.fromkeys(
                item.strip().lower() for item in declared_types
            )
        )

        extractor.supported_artefact_types = normalised_types
        self._extractors[name] = extractor

    def register_module(self, module_path: str) -> int:
        """Import one extractor module and register its exported instances.

        Returns the number of newly registered extractors.
        """
        if module_path in self._modules:
            return self._modules[module_path]["registered_count"]

        record: dict[str, Any] = {
            "module": module_path,
            "status": "loading",
            "registered_count": 0,
            "error": None,
        }
        self._modules[module_path] = record

        try:
            module = importlib.import_module(module_path)

            if callable(getattr(module, "register_extractors", None)):
                before = len(self._extractors)
                module.register_extractors(self)
                count = len(self._extractors) - before

            else:
                instances = []

                single = getattr(module, "EXTRACTOR", None)
                multiple = getattr(module, "EXTRACTORS", None)

                if single is not None:
                    instances.append(single)

                if multiple is not None:
                    if isinstance(multiple, (str, bytes)):
                        raise RegistryError(
                            f"{module_path}.EXTRACTORS must be an iterable "
                            "of extractor instances."
                        )
                    instances.extend(list(multiple))

                before = len(self._extractors)
                for extractor in instances:
                    self.register(extractor)
                count = len(self._extractors) - before

            record["status"] = "loaded" if count else "no_extractors"
            record["registered_count"] = count
            return count

        except Exception as exc:
            record["status"] = "failed"
            record["error"] = f"{type(exc).__name__}: {exc}"
            return 0

    def discover(self) -> dict[str, dict[str, Any]]:
        """Attempt to load every module in the declared inventory.

        Missing files and modules that cannot import are reported in the
        inventory; they are not treated as operational extractors.
        """
        for category, module_names in EXTRACTOR_MODULES.items():
            for module_name in module_names:
                module_path = self._module_path(category, module_name)
                self.register_module(module_path)

        return self.inventory()

    def get_compatible(self, artefact_type: str) -> list[Any]:
        """Return all registered extractors supporting this artefact type."""
        if not isinstance(artefact_type, str) or not artefact_type.strip():
            raise ValueError("artefact_type must be a non-empty string.")

        requested_type = artefact_type.strip().lower()

        return [
            extractor
            for extractor in self._extractors.values()
            if requested_type in extractor.supported_artefact_types
        ]

    def get(self, name: str) -> Any:
        """Return a registered extractor by its unique name."""
        try:
            return self._extractors[name]
        except KeyError as exc:
            raise RegistryError(
                f"No extractor named '{name}' is registered."
            ) from exc

    def supports(self, artefact_type: str) -> bool:
        """Return whether any registered extractor supports this type."""
        return bool(self.get_compatible(artefact_type))

    def list_extractors(self) -> list[dict[str, Any]]:
        """List successfully registered extractors and their capabilities."""
        return [
            {
                "name": extractor.name,
                "module": extractor.__class__.__module__,
                "supported_artefact_types": list(
                    extractor.supported_artefact_types
                ),
            }
            for extractor in self._extractors.values()
        ]

    def inventory(self) -> dict[str, dict[str, Any]]:
        """Report the load status of every discovered or attempted module."""
        return {
            module_path: record.copy()
            for module_path, record in self._modules.items()
        }

    def unregister(self, name: str) -> Any:
        """Remove a registered extractor by name."""
        try:
            return self._extractors.pop(name)
        except KeyError as exc:
            raise RegistryError(
                f"No extractor named '{name}' is registered."
            ) from exc

    def clear(self) -> None:
        """Clear registered extractor instances and module load records."""
        self._extractors.clear()
        self._modules.clear()

    def __len__(self) -> int:
        return len(self._extractors)

    def __contains__(self, name: str) -> bool:
        return name in self._extractors