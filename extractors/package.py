from __future__ import annotations

import ast
import configparser
import hashlib
import json
import re
import tomllib
import xml.etree.ElementTree as ET

from email import policy
from email.parser import BytesParser
from pathlib import Path
from typing import Any

from core.packets import Packet, PacketStatus

def _normalise_dependency(name: str, version: str | None = None) -> dict:
    return {
        "name": name.strip(),
        "version_constraint": version.strip() if version else None,
    }

def _parse_requirement(requirement: str) -> dict:
    """
    Parse a basic PEP 508-style requirement without resolving markers,
    extras, or URLs.
    """
    requirement = requirement.strip()

    match = re.match(
        r"^([A-Za-z0-9][A-Za-z0-9._-]*)"
        r"(?:\[[^\]]+\])?\s*(.*)$",
        requirement,
    )

    if not match:
        return {
            "name": requirement,
            "version_constraint": None,
        }

    constraint = match.group(2).strip() or None

    if constraint and ";" in constraint:
        constraint = constraint.split(";", 1)[0].strip() or None

    return _normalise_dependency(match.group(1), constraint)

def _parse_python(path: Path, raw: bytes) -> dict:
    filename = path.name.lower()
    data: dict[str, Any] = {
        "package_name": None,
        "version": None,
        "ecosystem": "PyPI",
        "dependencies": [],
        "dependency_source": "declared",
    }

    if filename == "pyproject.toml":
        document = tomllib.loads(raw.decode("utf-8"))
        project = document.get("project", {})
        poetry = document.get("tool", {}).get("poetry", {})

        data["package_name"] = project.get("name") or poetry.get("name")
        data["version"] = project.get("version") or poetry.get("version")

        dependencies = project.get("dependencies", [])

        for requirement in dependencies:
            if isinstance(requirement, str):
                data["dependencies"].append(
                    _parse_requirement(requirement)
                )

        optional = project.get("optional-dependencies", {})
        for group, requirements in optional.items():
            for requirement in requirements:
                if isinstance(requirement, str):
                    dependency = _parse_requirement(requirement)
                    dependency["group"] = group
                    data["dependencies"].append(dependency)

        if not dependencies and isinstance(poetry.get("dependencies"), dict):
            for name, constraint in poetry["dependencies"].items():
                if name.lower() == "python":
                    continue

                if isinstance(constraint, str):
                    version_constraint = constraint
                elif isinstance(constraint, dict):
                    version_constraint = constraint.get("version")
                else:
                    version_constraint = None

                data["dependencies"].append(
                    _normalise_dependency(name, version_constraint)
                )

        return data

    if filename == "setup.cfg":
        config = configparser.ConfigParser()
        config.read_string(raw.decode("utf-8", errors="replace"))

        if config.has_section("metadata"):
            data["package_name"] = config.get(
                "metadata", "name", fallback=None
            )
            data["version"] = config.get(
                "metadata", "version", fallback=None
            )

        if config.has_section("options"):
            requirements = config.get(
                "options", "install_requires", fallback=""
            )

            for requirement in requirements.splitlines():
                requirement = requirement.strip()
                if requirement and not requirement.startswith("#"):
                    data["dependencies"].append(
                        _parse_requirement(requirement)
                    )

        return data

    if filename == "pkg-info":
        message = BytesParser(policy=policy.default).parsebytes(raw)
        data["package_name"] = message.get("Name")
        data["version"] = message.get("Version")

        for requirement in message.get_all("Requires-Dist", []):
            data["dependencies"].append(
                _parse_requirement(str(requirement))
            )

        return data

    if filename == "setup.py":
        # Static AST inspection only. Never execute setup.py.
        tree = ast.parse(raw.decode("utf-8", errors="replace"))

        assignments: dict[str, Any] = {}
        setup_call = None

        for node in ast.walk(tree):
            if isinstance(node, (ast.Assign, ast.AnnAssign)):
                value_node = node.value

                if value_node is None:
                    continue

                try:
                    value = ast.literal_eval(value_node)
                except (ValueError, TypeError):
                    continue

                targets = (
                    node.targets
                    if isinstance(node, ast.Assign)
                    else [node.target]
                )

                for target in targets:
                    if isinstance(target, ast.Name):
                        assignments[target.id] = value

            elif isinstance(node, ast.Call):
                function = node.func
                if (
                    isinstance(function, ast.Name)
                    and function.id == "setup"
                ):
                    setup_call = node

        if setup_call:
            for keyword in setup_call.keywords:
                if keyword.arg not in {"name", "version", "install_requires"}:
                    continue

                try:
                    value = ast.literal_eval(keyword.value)
                except (ValueError, TypeError):
                    continue

                if keyword.arg == "name":
                    data["package_name"] = value
                elif keyword.arg == "version":
                    data["version"] = value
                elif keyword.arg == "install_requires" and isinstance(value, list):
                    data["dependencies"].extend(
                        _parse_requirement(item)
                        for item in value
                        if isinstance(item, str)
                    )

        # Resolve simple variable references used in setup().
        if setup_call:
            for keyword in setup_call.keywords:
                if keyword.arg not in {"name", "version", "install_requires"}:
                    continue

                if not isinstance(keyword.value, ast.Name):
                    continue

                value = assignments.get(keyword.value.id)

                if keyword.arg in {"name", "version"} and isinstance(value, str):
                    data[
                        "package_name" if keyword.arg == "name" else "version"
                    ] = value

                elif keyword.arg == "install_requires" and isinstance(value, list):
                    data["dependencies"].extend(
                        _parse_requirement(item)
                        for item in value
                        if isinstance(item, str)
                    )

        return data

    raise ValueError(f"Unsupported Python manifest: {filename}")

def _parse_npm(path: Path, raw: bytes) -> dict:
    document = json.loads(raw.decode("utf-8"))
    filename = path.name.lower()

    data = {
        "package_name": document.get("name"),
        "version": document.get("version"),
        "ecosystem": "npm",
        "dependencies": [],
        "dependency_source": "declared",
    }

    if filename == "package.json":
        groups = (
            "dependencies",
            "devDependencies",
            "peerDependencies",
            "optionalDependencies",
        )

        for group in groups:
            for name, constraint in document.get(group, {}).items():
                dependency = _normalise_dependency(name, str(constraint))
                dependency["group"] = group
                data["dependencies"].append(dependency)

        return data

    # package-lock.json
    data["dependency_source"] = "lockfile"

    packages = document.get("packages", {})
    if isinstance(packages, dict):
        for package_path, package_data in packages.items():
            if not package_path or not isinstance(package_data, dict):
                continue

            name = package_data.get("name")
            if not name:
                name = package_path.rsplit("node_modules/", 1)[-1]

            if not name:
                continue

            dependency = _normalise_dependency(
                name,
                package_data.get("version"),
            )
            dependency["path"] = package_path
            data["dependencies"].append(dependency)

    else:
        _parse_npm_legacy_dependencies(
            document.get("dependencies", {}),
            data["dependencies"],
        )

    return data

def _parse_npm_legacy_dependencies(
    dependencies: dict,
    output: list,
    prefix: str = "",
) -> None:
    for name, details in dependencies.items():
        if not isinstance(details, dict):
            continue

        output.append(
            _normalise_dependency(name, details.get("version"))
        )

        _parse_npm_legacy_dependencies(
            details.get("dependencies", {}),
            output,
            prefix,
        )

def _parse_rust(path: Path, raw: bytes) -> dict:
    document = tomllib.loads(raw.decode("utf-8"))
    filename = path.name.lower()

    if filename == "cargo.toml":
        package = document.get("package", {})
        dependencies = []

        for group in (
            "dependencies",
            "dev-dependencies",
            "build-dependencies",
        ):
            for name, details in document.get(group, {}).items():
                constraint = (
                    details.get("version")
                    if isinstance(details, dict)
                    else details
                )
                dependency = _normalise_dependency(name, constraint)
                dependency["group"] = group
                dependencies.append(dependency)

        for target_data in document.get("target", {}).values():
            for group in (
                "dependencies",
                "dev-dependencies",
                "build-dependencies",
            ):
                for name, details in target_data.get(group, {}).items():
                    constraint = (
                        details.get("version")
                        if isinstance(details, dict)
                        else details
                    )
                    dependency = _normalise_dependency(name, constraint)
                    dependency["group"] = group
                    dependencies.append(dependency)

        return {
            "package_name": package.get("name"),
            "version": package.get("version"),
            "ecosystem": "Cargo",
            "dependencies": dependencies,
            "dependency_source": "declared",
        }

    # Cargo.lock
    packages = document.get("package", [])
    dependencies = []

    for package in packages:
        if package.get("name") == document.get("package_name"):
            continue

        dependencies.append(
            _normalise_dependency(
                package.get("name", ""),
                package.get("version"),
            )
        )

    return {
        "package_name": None,
        "version": None,
        "ecosystem": "Cargo",
        "dependencies": dependencies,
        "dependency_source": "lockfile",
    }

def _parse_php(path: Path, raw: bytes) -> dict:
    document = json.loads(raw.decode("utf-8"))
    filename = path.name.lower()

    if filename == "composer.json":
        groups = (
            "require",
            "require-dev",
        )
        dependencies = []

        for group in groups:
            for name, constraint in document.get(group, {}).items():
                if name.lower() == "php":
                    continue

                dependency = _normalise_dependency(name, str(constraint))
                dependency["group"] = group
                dependencies.append(dependency)

        return {
            "package_name": document.get("name"),
            "version": document.get("version"),
            "ecosystem": "Packagist",
            "dependencies": dependencies,
            "dependency_source": "declared",
        }

    # composer.lock
    dependencies = []

    for group in ("packages", "packages-dev"):
        for package in document.get(group, []):
            dependencies.append(
                _normalise_dependency(
                    package.get("name", ""),
                    package.get("version"),
                )
            )

    return {
        "package_name": document.get("name"),
        "version": document.get("version"),
        "ecosystem": "Packagist",
        "dependencies": dependencies,
        "dependency_source": "lockfile",
    }

def _parse_maven(path: Path, raw: bytes) -> dict:
    root = ET.fromstring(raw)
    namespace = ""

    if root.tag.startswith("{"):
        namespace = root.tag.split("}", 1)[0] + "}"

    def find_text(element, name):
        child = element.find(f"{namespace}{name}")
        return child.text.strip() if child is not None and child.text else None

    properties = root.find(f"{namespace}properties")
    property_values = {}

    if properties is not None:
        for child in properties:
            property_values[child.tag.split("}")[-1]] = (
                child.text.strip() if child.text else None
            )

    def resolve(value):
        if not value:
            return None

        return re.sub(
            r"\$\{([^}]+)\}",
            lambda match: str(property_values.get(match.group(1), match.group(0))),
            value,
        )

    group_id = resolve(find_text(root, "groupId"))
    artifact_id = find_text(root, "artifactId")
    version = resolve(find_text(root, "version"))

    parent = root.find(f"{namespace}parent")
    if parent is not None:
        group_id = group_id or resolve(find_text(parent, "groupId"))
        version = version or resolve(find_text(parent, "version"))

    dependencies = []
    dependency_section = root.find(f"{namespace}dependencies")

    if dependency_section is not None:
        for dependency in dependency_section.findall(
            f"{namespace}dependency"
        ):
            name = find_text(dependency, "artifactId")
            group = find_text(dependency, "groupId")
            constraint = resolve(find_text(dependency, "version"))

            if name:
                item = _normalise_dependency(
                    f"{group}:{name}" if group else name,
                    constraint,
                )
                scope = find_text(dependency, "scope")
                if scope:
                    item["group"] = scope
                dependencies.append(item)

    return {
        "package_name": (
            f"{group_id}:{artifact_id}"
            if group_id and artifact_id
            else artifact_id
        ),
        "version": version,
        "ecosystem": "Maven",
        "dependencies": dependencies,
        "dependency_source": "declared",
    }

def _parse_ruby(path: Path, raw: bytes) -> dict:
    filename = path.name.lower()
    text = raw.decode("utf-8", errors="replace")

    if filename.endswith(".gemspec"):
        # Static extraction only. No Ruby execution.
        name = re.search(
            r"\.name\s*=\s*['\"]([^'\"]+)['\"]",
            text,
        )
        version = re.search(
            r"\.version\s*=\s*['\"]([^'\"]+)['\"]",
            text,
        )
        dependencies = []

        for match in re.finditer(
            r"add_(?:runtime_)?dependency\s*"
            r"\(?\s*['\"]([^'\"]+)['\"]"
            r"(?:\s*,\s*['\"]([^'\"]+)['\"])?",
            text,
        ):
            dependencies.append(
                _normalise_dependency(match.group(1), match.group(2))
            )

        return {
            "package_name": name.group(1) if name else None,
            "version": version.group(1) if version else None,
            "ecosystem": "RubyGems",
            "dependencies": dependencies,
            "dependency_source": "declared",
        }

    # Gemfile.lock
    dependencies = []
    package_name = None
    version = None
    in_specs = False

    for line in text.splitlines():
        if line.strip() == "specs:":
            in_specs = True
            continue

        if in_specs:
            if line and not line.startswith(" "):
                in_specs = False
            else:
                match = re.match(r"^\s{4}([A-Za-z0-9_.-]+)\s+\(([^)]+)\)", line)
                if match:
                    dependencies.append(
                        _normalise_dependency(match.group(1), match.group(2))
                    )

        if line.startswith("    ") and not package_name:
            match = re.match(r"^\s{4}([A-Za-z0-9_.-]+)\s+\(([^)]+)\)", line)
            if match:
                package_name = match.group(1)
                version = match.group(2)

    return {
        "package_name": package_name,
        "version": version,
        "ecosystem": "RubyGems",
        "dependencies": dependencies,
        "dependency_source": "lockfile",
    }

PARSERS = {
    "pyproject.toml": _parse_python,
    "setup.cfg": _parse_python,
    "setup.py": _parse_python,
    "pkg-info": _parse_python,
    "package.json": _parse_npm,
    "package-lock.json": _parse_npm,
    "cargo.toml": _parse_rust,
    "cargo.lock": _parse_rust,
    "composer.json": _parse_php,
    "composer.lock": _parse_php,
    "pom.xml": _parse_maven,
}

def packageextract(packet: Packet) -> Packet:
    result = packet.child(
        stage="extraction",
        artefact_type="package",
        status=PacketStatus.RUNNING,
    )

    try:
        source = packet.input

        if not isinstance(source, str) or not source.strip():
            raise ValueError("A package manifest file path is required.")

        path = Path(source).expanduser()

        if not path.exists():
            raise FileNotFoundError(f"Package manifest not found: {path}")

        if not path.is_file():
            raise ValueError("Package input must be a file.")

        filename = path.name.lower()

        if filename.endswith(".gemspec"):
            parser = _parse_ruby
        elif filename == "gemfile.lock":
            parser = _parse_ruby
        elif filename == "pom.xml":
            parser = _parse_maven
        else:
            parser = PARSERS.get(filename)

        if parser is None:
            raise ValueError(
                f"Unsupported package manifest: {filename}"
            )

        raw = path.read_bytes()
        extracted = parser(path, raw)

        extracted["manifest"] = {
            "filename": path.name,
            "path": str(path.resolve()),
            "size": len(raw),
            "sha256": hashlib.sha256(raw).hexdigest(),
        }

        extracted["package_name"] = extracted.get("package_name")
        extracted["version"] = extracted.get("version")
        extracted["dependencies"] = extracted.get("dependencies", [])

        if not extracted["package_name"]:
            result.add_error(
                code="PACKAGE_NAME_NOT_FOUND",
                message="The manifest did not contain a statically identifiable package name.",
                component="extractors.package",
            )

        if not extracted["version"]:
            result.add_error(
                code="PACKAGE_VERSION_NOT_FOUND",
                message="The manifest did not contain a statically identifiable package version.",
                component="extractors.package",
            )

        result.data = extracted

        if result.errors:
            result.status = PacketStatus.PARTIAL_SUCCESS
        else:
            result.status = PacketStatus.SUCCESS

    except FileNotFoundError as exc:
        result.add_error(
            code="PACKAGE_FILE_NOT_FOUND",
            message=str(exc),
            component="extractors.package",
        )
        result.status = PacketStatus.FAILED

    except PermissionError as exc:
        result.add_error(
            code="PACKAGE_PERMISSION_DENIED",
            message=str(exc),
            component="extractors.package",
        )
        result.status = PacketStatus.FAILED

    except (json.JSONDecodeError, tomllib.TOMLDecodeError, ET.ParseError) as exc:
        result.add_error(
            code="INVALID_PACKAGE_MANIFEST",
            message=str(exc),
            component="extractors.package",
        )
        result.status = PacketStatus.FAILED

    except (OSError, UnicodeDecodeError, ValueError, SyntaxError) as exc:
        result.add_error(
            code="PACKAGE_EXTRACTION_FAILED",
            message=str(exc),
            component="extractors.package",
        )
        result.status = PacketStatus.FAILED

    except Exception as exc:
        result.add_error(
            code="UNEXPECTED_PACKAGE_ERROR",
            message=str(exc),
            component="extractors.package",
        )
        result.status = PacketStatus.FAILED

    return result