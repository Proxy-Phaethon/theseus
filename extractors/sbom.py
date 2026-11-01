from __future__ import annotations

import hashlib
import json
import re
import xml.etree.ElementTree as ET

from pathlib import Path
from typing import Any

from core.packets import Packet, PacketStatus

def _text(element, name: str) -> str | None:
    value = element.find(name)
    if value is None or value.text is None:
        return None
    return value.text.strip() or None

def _hash_file(path: Path) -> dict:
    hashes = {
        "md5": hashlib.md5(),
        "sha1": hashlib.sha1(),
        "sha256": hashlib.sha256(),
        "sha512": hashlib.sha512(),
    }

    with path.open("rb") as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b""):
            for digest in hashes.values():
                digest.update(chunk)

    return {
        name: digest.hexdigest()
        for name, digest in hashes.items()
    }

def _normalise_hashes(values: Any) -> list[dict]:
    output = []

    if isinstance(values, dict):
        values = [
            {"alg": algorithm, "content": value}
            for algorithm, value in values.items()
        ]

    if not isinstance(values, list):
        return output

    for item in values:
        if not isinstance(item, dict):
            continue

        algorithm = item.get("alg") or item.get("algorithm")
        content = item.get("content") or item.get("checksumValue")

        if algorithm or content:
            output.append({
                "algorithm": algorithm,
                "value": content,
            })

    return output

def _normalise_licenses(values: Any) -> list:
    output = []

    if not isinstance(values, list):
        values = [values] if values else []

    for item in values:
        if isinstance(item, str):
            output.append({"id": item, "name": None, "url": None})
        elif isinstance(item, dict):
            license_data = item.get("license", item)
            if not isinstance(license_data, dict):
                continue

            output.append({
                "id": license_data.get("id"),
                "name": license_data.get("name"),
                "url": license_data.get("url"),
            })

    return output

def _cyclonedx_component(component: dict) -> dict:
    if not isinstance(component, dict):
        return {}

    supplier = component.get("supplier")
    publisher = component.get("publisher")

    hashes = _normalise_hashes(component.get("hashes"))
    licenses = _normalise_licenses(component.get("licenses"))

    external_references = []

    for reference in component.get("externalReferences", []):
        if isinstance(reference, dict):
            external_references.append({
                "type": reference.get("type"),
                "url": reference.get("url"),
                "comment": reference.get("comment"),
            })

    properties = []

    for prop in component.get("properties", []):
        if isinstance(prop, dict):
            properties.append({
                "name": prop.get("name"),
                "value": prop.get("value"),
            })

    return {
        "bom_ref": component.get("bom-ref"),
        "type": component.get("type"),
        "name": component.get("name"),
        "version": component.get("version"),
        "group": component.get("group"),
        "description": component.get("description"),
        "publisher": publisher,
        "supplier": supplier,
        "purl": component.get("purl"),
        "cpe": component.get("cpe"),
        "scope": component.get("scope"),
        "hashes": hashes,
        "licenses": licenses,
        "external_references": external_references,
        "properties": properties,
        "copyright": component.get("copyright"),
        "bom_link": component.get("bomLink"),
    }

def _cyclonedx_xml_component(element, namespace: str) -> dict:
    def value(name):
        return _text(element, f"{namespace}{name}")

    supplier_element = element.find(f"{namespace}supplier")
    supplier = None

    if supplier_element is not None:
        supplier = {
            "name": _text(supplier_element, f"{namespace}name"),
            "url": [
                item.text
                for item in supplier_element.findall(f"{namespace}url")
                if item.text
            ],
        }

    hashes = []

    for item in element.findall(f"{namespace}hashes/{namespace}hash"):
        hashes.append({
            "alg": item.get("alg"),
            "content": item.text.strip() if item.text else None,
        })

    licenses = []

    for item in element.findall(f"{namespace}licenses/{namespace}license"):
        license_element = item.find(f"{namespace}id")
        if license_element is None:
            license_element = item.find(f"{namespace}name")

        if license_element is not None:
            licenses.append({
                "id": _text(item, f"{namespace}id"),
                "name": _text(item, f"{namespace}name"),
                "url": _text(item, f"{namespace}url"),
            })

    external_references = []

    for item in element.findall(
        f"{namespace}externalReferences/{namespace}reference"
    ):
        external_references.append({
            "type": item.get("type"),
            "url": _text(item, f"{namespace}url"),
            "comment": _text(item, f"{namespace}comment"),
        })

    return {
        "bom_ref": element.get("bom-ref"),
        "type": element.get("type"),
        "name": value("name"),
        "version": value("version"),
        "group": value("group"),
        "description": value("description"),
        "publisher": value("publisher"),
        "supplier": supplier,
        "purl": value("purl"),
        "cpe": value("cpe"),
        "scope": element.get("scope"),
        "hashes": hashes,
        "licenses": licenses,
        "external_references": external_references,
        "properties": [],
        "copyright": value("copyright"),
        "bom_link": None,
    }

def _extract_cyclonedx_json(document: dict) -> dict:
    metadata = document.get("metadata") or {}
    metadata_component = metadata.get("component")

    components = []

    def collect(items):
        for component in items or []:
            if not isinstance(component, dict):
                continue

            components.append(_cyclonedx_component(component))
            collect(component.get("components", []))

    collect(document.get("components", []))

    if isinstance(metadata_component, dict):
        metadata_component = _cyclonedx_component(metadata_component)

    dependencies = []

    for dependency in document.get("dependencies", []):
        if isinstance(dependency, dict):
            dependencies.append({
                "ref": dependency.get("ref"),
                "depends_on": dependency.get("dependsOn", []),
            })

    tools = metadata.get("tools", {})
    if isinstance(tools, list):
        tool_list = tools
    else:
        tool_list = tools.get("components", []) if isinstance(tools, dict) else []

    return {
        "format": "CycloneDX",
        "specification_version": document.get("specVersion"),
        "serial_number": document.get("serialNumber"),
        "document_version": document.get("version"),
        "metadata": {
            "timestamp": metadata.get("timestamp"),
            "component": metadata_component,
            "tools": tool_list,
            "authors": metadata.get("authors", []),
        },
        "components": components,
        "dependencies": dependencies,
        "vulnerabilities": document.get("vulnerabilities", []),
        "component_count": len(components),
    }

def _extract_cyclonedx_xml(root) -> dict:
    namespace = ""

    if root.tag.startswith("{"):
        namespace = root.tag.split("}", 1)[0] + "}"

    namespace_uri = (
        root.tag.split("}", 1)[0][1:]
        if root.tag.startswith("{")
        else ""
    )

    spec_version_match = re.search(
        r"/(\d+\.\d+)(?:/|$)",
        namespace_uri,
    )

    specification_version = (
        spec_version_match.group(1)
        if spec_version_match
        else None
    )

    metadata_element = root.find(f"{namespace}metadata")
    components_element = root.find(f"{namespace}components")

    components = []

    if components_element is not None:
        for component in components_element.findall(
            f"{namespace}component"
        ):
            components.append(
                _cyclonedx_xml_component(component, namespace)
            )

    dependencies = []

    dependencies_element = root.find(f"{namespace}dependencies")

    if dependencies_element is not None:
        for dependency in dependencies_element.findall(
            f"{namespace}dependency"
        ):
            dependencies.append({
                "ref": dependency.get("ref"),
                "depends_on": [
                    item.get("ref")
                    for item in dependency.findall(
                        f"{namespace}dependency"
                    )
                ],
            })

    metadata = {
        "timestamp": None,
        "component": None,
        "tools": [],
        "authors": [],
    }

    if metadata_element is not None:
        metadata["timestamp"] = _text(
            metadata_element, f"{namespace}timestamp"
        )

        component = metadata_element.find(f"{namespace}component")
        if component is not None:
            metadata["component"] = _cyclonedx_xml_component(
                component, namespace
            )

        tools_element = metadata_element.find(f"{namespace}tools")
        if tools_element is not None:
            metadata["tools"] = [
                {
                    "vendor": _text(item, f"{namespace}vendor"),
                    "name": _text(item, f"{namespace}name"),
                    "version": _text(item, f"{namespace}version"),
                }
                for item in tools_element.findall(f"{namespace}tool")
            ]

        authors_element = metadata_element.find(f"{namespace}authors")
        if authors_element is not None:
            metadata["authors"] = [
                _text(item, f"{namespace}name")
                for item in authors_element.findall(f"{namespace}author")
            ]

    return {
        "format": "CycloneDX",
        "specification_version": specification_version,
        "serial_number": root.get("serialNumber"),
        "document_version": root.get("version"),
        "metadata": metadata,
        "components": components,
        "dependencies": dependencies,
        "vulnerabilities": [],
        "component_count": len(components),
    }

def _spdx_package(package: dict) -> dict:
    external_ids = []

    for item in package.get("externalRefs", []):
        if isinstance(item, dict):
            external_ids.append({
                "category": item.get("referenceCategory"),
                "type": item.get("referenceType"),
                "locator": item.get("referenceLocator"),
            })

    checksums = []

    for item in package.get("checksums", []):
        if isinstance(item, dict):
            checksums.append({
                "algorithm": item.get("algorithm"),
                "value": item.get("checksumValue"),
            })

    return {
        "id": package.get("SPDXID"),
        "name": package.get("name"),
        "version": package.get("versionInfo"),
        "type": "package",
        "supplier": package.get("supplier"),
        "originator": package.get("originator"),
        "download_location": package.get("downloadLocation"),
        "files_analyzed": package.get("filesAnalyzed"),
        "source_info": package.get("sourceInfo"),
        "license_concluded": package.get("licenseConcluded"),
        "license_declared": package.get("licenseDeclared"),
        "copyright": package.get("copyrightText"),
        "checksums": checksums,
        "external_identifiers": external_ids,
        "purl": next(
            (
                item["locator"]
                for item in external_ids
                if item["type"] == "purl"
            ),
            None,
        ),
        "cpe": next(
            (
                item["locator"]
                for item in external_ids
                if item["type"] == "cpe22Type"
                or item["type"] == "cpe23Type"
            ),
            None,
        ),
    }

def _extract_spdx_json(document: dict) -> dict:
    packages = [
        _spdx_package(package)
        for package in document.get("packages", [])
        if isinstance(package, dict)
    ]

    relationships = []

    for relationship in document.get("relationships", []):
        if isinstance(relationship, dict):
            relationships.append({
                "source": relationship.get("spdxElementId"),
                "type": relationship.get("relationshipType"),
                "target": relationship.get("relatedSpdxElement"),
                "comment": relationship.get("comment"),
            })

    creation = document.get("creationInfo", {})

    return {
        "format": "SPDX",
        "specification_version": document.get("spdxVersion"),
        "document": {
            "name": document.get("name"),
            "namespace": document.get("documentNamespace"),
            "spdx_id": document.get("SPDXID"),
            "data_license": document.get("dataLicense"),
            "creation_info": creation,
            "external_document_refs": document.get(
                "externalDocumentRefs", []
            ),
            "annotations": document.get("annotations", []),
        },
        "components": packages,
        "dependencies": relationships,
        "component_count": len(packages),
    }

def _extract_spdx_tag_value(text: str) -> dict:
    document = {}
    packages = []
    relationships = []

    current_package = None

    for line in text.splitlines():
        if not line.strip():
            continue

        if line.startswith("PackageName:"):
            if current_package:
                packages.append(current_package)

            current_package = {
                "name": line.split(":", 1)[1].strip(),
                "type": "package",
                "checksums": [],
                "external_identifiers": [],
            }
            continue

        if line.startswith("Relationship:"):
            parts = line.split()
            if len(parts) >= 4:
                relationships.append({
                    "source": parts[1],
                    "type": parts[2],
                    "target": parts[3],
                    "comment": None,
                })
            continue

        if ":" not in line:
            continue

        key, value = line.split(":", 1)
        value = value.strip()

        if current_package is not None:
            field_map = {
                "SPDXID": "id",
                "PackageVersion": "version",
                "PackageSupplier": "supplier",
                "PackageOriginator": "originator",
                "PackageDownloadLocation": "download_location",
                "FilesAnalyzed": "files_analyzed",
                "PackageSourceInfo": "source_info",
                "PackageLicenseConcluded": "license_concluded",
                "PackageLicenseDeclared": "license_declared",
                "PackageCopyrightText": "copyright",
            }

            if key in field_map:
                current_package[field_map[key]] = value

            elif key == "PackageChecksum":
                parts = value.split(":", 1)
                if len(parts) == 2:
                    current_package["checksums"].append({
                        "algorithm": parts[0],
                        "value": parts[1],
                    })

            elif key == "ExternalRef":
                parts = value.split(None, 2)
                if len(parts) == 3:
                    current_package["external_identifiers"].append({
                        "category": parts[0],
                        "type": parts[1],
                        "locator": parts[2],
                    })

        else:
            document[key] = value

    if current_package:
        packages.append(current_package)

    for package in packages:
        identifiers = package.get("external_identifiers", [])
        package["purl"] = next(
            (
                item["locator"]
                for item in identifiers
                if item["type"] == "purl"
            ),
            None,
        )
        package["cpe"] = next(
            (
                item["locator"]
                for item in identifiers
                if item["type"] in {"cpe22Type", "cpe23Type"}
            ),
            None,
        )

    return {
        "format": "SPDX",
        "specification_version": document.get("SPDXVersion"),
        "document": {
            "name": document.get("DocumentName"),
            "namespace": document.get("DocumentNamespace"),
            "spdx_id": document.get("SPDXID"),
            "data_license": document.get("DataLicense"),
            "creation_info": {
                "created": document.get("CreationDate"),
                "creators": [
                    value
                    for key, value in document.items()
                    if key == "Creator"
                ],
            },
            "external_document_refs": [],
            "annotations": [],
        },
        "components": packages,
        "dependencies": relationships,
        "component_count": len(packages),
    }

def _extract_spdx_yaml(raw: bytes) -> dict:
    try:
        import yaml
    except ImportError as exc:
        raise ValueError(
            "YAML SBOM parsing requires PyYAML. Install it with: pip install PyYAML"
        ) from exc

    try:
        document = yaml.safe_load(raw.decode("utf-8"))
    except yaml.YAMLError as exc:
        raise ValueError(f"Invalid SPDX YAML: {exc}") from exc

    return _extract_spdx_json(document)

def _parse_sbom(path: Path, raw: bytes) -> dict:
    filename = path.name.lower()

    if filename.endswith(".spdx"):
        return _extract_spdx_tag_value(
            raw.decode("utf-8-sig", errors="replace")
        )

    if filename.endswith((".yaml", ".yml")):
        return _extract_spdx_yaml(raw)

    if filename.endswith(".xml"):
        root = ET.fromstring(raw)
        root_name = root.tag.split("}")[-1].lower()

        if root_name != "bom":
            raise ValueError("XML document is not a recognised CycloneDX BOM.")

        return _extract_cyclonedx_xml(root)

    if filename.endswith(".json"):
        document = json.loads(raw.decode("utf-8-sig"))

        if not isinstance(document, dict):
            raise ValueError("SBOM JSON must contain an object.")

        if document.get("bomFormat", "").lower() == "cyclonedx":
            return _extract_cyclonedx_json(document)

        if document.get("spdxVersion"):
            return _extract_spdx_json(document)

        raise ValueError("Unrecognised JSON SBOM format.")

    raise ValueError(f"Unsupported SBOM file extension: {path.suffix}")

def sbomextract(packet: Packet) -> Packet:
    result = packet.child(
        stage="extraction",
        artefact_type="sbom",
        status=PacketStatus.RUNNING,
    )

    try:
        source = packet.input

        if not isinstance(source, str) or not source.strip():
            raise ValueError("An SBOM file path is required.")

        path = Path(source).expanduser()

        if not path.exists():
            raise FileNotFoundError(f"SBOM file not found: {path}")

        if not path.is_file():
            raise ValueError("SBOM input must be a file.")

        raw = path.read_bytes()

        if not raw:
            raise ValueError("SBOM file is empty.")

        extracted = _parse_sbom(path, raw)

        extracted["source_file"] = {
            "filename": path.name,
            "path": str(path.resolve()),
            "size": len(raw),
            "hashes": _hash_file(path),
        }

        extracted["component_count"] = len(
            extracted.get("components", [])
        )

        if not extracted.get("specification_version"):
            result.add_error(
                code="SBOM_VERSION_NOT_FOUND",
                message="The SBOM specification version was not present.",
                component="extractors.sbom",
            )

        if not extracted.get("components"):
            result.add_error(
                code="SBOM_COMPONENTS_NOT_FOUND",
                message="No components were recorded in the SBOM.",
                component="extractors.sbom",
            )

        result.data = extracted
        result.status = (
            PacketStatus.PARTIAL_SUCCESS
            if result.errors
            else PacketStatus.SUCCESS
        )

    except FileNotFoundError as exc:
        result.add_error(
            code="SBOM_FILE_NOT_FOUND",
            message=str(exc),
            component="extractors.sbom",
        )
        result.status = PacketStatus.FAILED

    except PermissionError as exc:
        result.add_error(
            code="SBOM_PERMISSION_DENIED",
            message=str(exc),
            component="extractors.sbom",
        )
        result.status = PacketStatus.FAILED

    except (json.JSONDecodeError, ET.ParseError) as exc:
        result.add_error(
            code="INVALID_SBOM_DOCUMENT",
            message=str(exc),
            component="extractors.sbom",
        )
        result.status = PacketStatus.FAILED

    except (OSError, UnicodeDecodeError, ValueError, TypeError) as exc:
        result.add_error(
            code="SBOM_EXTRACTION_FAILED",
            message=str(exc),
            component="extractors.sbom",
        )
        result.status = PacketStatus.FAILED

    except Exception as exc:
        result.add_error(
            code="UNEXPECTED_SBOM_ERROR",
            message=str(exc),
            component="extractors.sbom",
        )
        result.status = PacketStatus.FAILED

    return result