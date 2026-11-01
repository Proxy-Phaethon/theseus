from __future__ import annotations

import hashlib
import json
import re
import tarfile

from pathlib import Path
from typing import Any

from core.packets import Packet, PacketStatus

def _hash_file(path: Path) -> dict:
    hashes = {
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

def _load_yaml(raw: bytes) -> list:
    try:
        import yaml
    except ImportError as exc:
        raise ValueError(
            "YAML parsing requires PyYAML. Install it with: pip install PyYAML"
        ) from exc

    try:
        documents = list(
            yaml.safe_load_all(raw.decode("utf-8-sig"))
        )
    except yaml.YAMLError as exc:
        raise ValueError(f"Invalid YAML document: {exc}") from exc

    return [item for item in documents if isinstance(item, dict)]

def _parse_image_reference(reference: str | None) -> dict | None:
    if not isinstance(reference, str) or not reference.strip():
        return None

    reference = reference.strip()

    digest = None
    if "@" in reference:
        reference, digest = reference.rsplit("@", 1)

    slash_index = reference.rfind("/")
    colon_index = reference.rfind(":")

    if colon_index > slash_index:
        repository = reference[:colon_index]
        tag = reference[colon_index + 1:]
    else:
        repository = reference
        tag = None

    parts = repository.split("/")
    registry = None

    if len(parts) > 1 and (
        "." in parts[0]
        or ":" in parts[0]
        or parts[0] == "localhost"
    ):
        registry = parts.pop(0)

    return {
        "original": reference + (f"@{digest}" if digest else ""),
        "registry": registry,
        "repository": "/".join(parts),
        "tag": tag,
        "digest": digest,
    }

def _parse_dockerfile(raw: bytes) -> dict:
    text = raw.decode("utf-8-sig", errors="replace")

    instructions = []
    errors = []
    escape_character = "\\"

    lines = text.splitlines()
    logical_lines = []
    current = ""

    for line_number, line in enumerate(lines, start=1):
        stripped = line.strip()

        if stripped.startswith("#"):
            directive = re.match(
                r"#\s*escape\s*=\s*([\\`])",
                stripped,
                re.IGNORECASE,
            )
            if directive:
                escape_character = directive.group(1)
            continue

        if not stripped:
            continue

        if current:
            current += " " + stripped
        else:
            current = stripped

        if current.endswith(escape_character):
            current = current[:-1].rstrip()
            continue

        logical_lines.append((line_number, current))
        current = ""

    if current:
        logical_lines.append((len(lines), current))

    stages = []
    current_stage = None

    for line_number, instruction in logical_lines:
        match = re.match(
            r"^([A-Za-z]+)\s+(.*)$",
            instruction,
            re.DOTALL,
        )

        if not match:
            errors.append({
                "line": line_number,
                "message": "Unrecognised Dockerfile instruction.",
            })
            continue

        command = match.group(1).upper()
        arguments = match.group(2).strip()

        item = {
            "instruction": command,
            "arguments": arguments,
            "line": line_number,
        }

        instructions.append(item)

        if command == "FROM":
            from_match = re.match(
                r"^(?:--platform=(\S+)\s+)?(\S+)"
                r"(?:\s+AS\s+(\S+))?",
                arguments,
                re.IGNORECASE,
            )

            if from_match:
                current_stage = {
                    "base_image": from_match.group(2),
                    "image": _parse_image_reference(from_match.group(2)),
                    "platform": from_match.group(1),
                    "name": from_match.group(3),
                    "line": line_number,
                }
                stages.append(current_stage)

        elif command == "EXPOSE":
            if current_stage is not None:
                current_stage.setdefault("exposed_ports", []).extend(
                    arguments.split()
                )

        elif command == "ENV":
            if current_stage is not None:
                current_stage.setdefault("environment", []).append(
                    arguments
                )

        elif command == "VOLUME":
            if current_stage is not None:
                current_stage.setdefault("volumes", []).append(
                    arguments
                )

        elif command == "WORKDIR":
            if current_stage is not None:
                current_stage["working_directory"] = arguments

        elif command == "USER":
            if current_stage is not None:
                current_stage["user"] = arguments

        elif command == "ENTRYPOINT":
            if current_stage is not None:
                current_stage["entrypoint"] = arguments

        elif command == "CMD":
            if current_stage is not None:
                current_stage["command"] = arguments

        elif command == "LABEL":
            if current_stage is not None:
                current_stage.setdefault("labels", []).append(
                    arguments
                )

        elif command == "ARG":
            if current_stage is not None:
                current_stage.setdefault("build_arguments", []).append(
                    arguments
                )

        elif command == "COPY":
            if current_stage is not None:
                current_stage.setdefault("copy_instructions", []).append(
                    arguments
                )

        elif command == "ADD":
            if current_stage is not None:
                current_stage.setdefault("add_instructions", []).append(
                    arguments
                )

    return {
        "format": "Dockerfile",
        "syntax_directive": None,
        "instructions": instructions,
        "build_stages": stages,
        "instruction_count": len(instructions),
        "stage_count": len(stages),
        "parse_errors": errors,
    }

def _parse_compose_service(name: str, service: dict) -> dict:
    if not isinstance(service, dict):
        return {}

    build = service.get("build")

    if isinstance(build, str):
        build = {"context": build}
    elif not isinstance(build, dict):
        build = None

    environment = service.get("environment", {})
    if isinstance(environment, list):
        environment = {
            item.split("=", 1)[0]: (
                item.split("=", 1)[1]
                if "=" in item else None
            )
            for item in environment
        }

    ports = service.get("ports", [])
    volumes = service.get("volumes", [])

    depends_on = service.get("depends_on", [])

    if isinstance(depends_on, dict):
        depends_on = list(depends_on.keys())

    return {
        "name": name,
        "image": service.get("image"),
        "image_reference": _parse_image_reference(
            service.get("image")
        ),
        "build": build,
        "container_name": service.get("container_name"),
        "command": service.get("command"),
        "entrypoint": service.get("entrypoint"),
        "environment": environment,
        "ports": ports,
        "volumes": volumes,
        "networks": service.get("networks", []),
        "depends_on": depends_on,
        "restart": service.get("restart"),
        "healthcheck": service.get("healthcheck"),
        "privileged": service.get("privileged"),
        "user": service.get("user"),
        "working_dir": service.get("working_dir"),
        "labels": service.get("labels", {}),
        "platform": service.get("platform"),
        "profiles": service.get("profiles", []),
    }

def _parse_compose(document: dict) -> dict:
    services = []

    for name, service in document.get("services", {}).items():
        parsed = _parse_compose_service(name, service)
        if parsed:
            services.append(parsed)

    networks = document.get("networks", {})
    volumes = document.get("volumes", {})
    configs = document.get("configs", {})
    secrets = document.get("secrets", {})

    return {
        "format": "Docker Compose",
        "version": document.get("version"),
        "name": document.get("name"),
        "services": services,
        "networks": networks,
        "volumes": volumes,
        "configs": configs,
        "secrets": secrets,
        "service_count": len(services),
    }

def _parse_kubernetes_container(container: dict) -> dict:
    if not isinstance(container, dict):
        return {}

    return {
        "name": container.get("name"),
        "image": container.get("image"),
        "image_reference": _parse_image_reference(
            container.get("image")
        ),
        "image_pull_policy": container.get("imagePullPolicy"),
        "command": container.get("command"),
        "args": container.get("args"),
        "working_directory": container.get("workingDir"),
        "ports": container.get("ports", []),
        "environment": container.get("env", []),
        "environment_from": container.get("envFrom", []),
        "volume_mounts": container.get("volumeMounts", []),
        "resources": container.get("resources", {}),
        "security_context": container.get("securityContext", {}),
        "readiness_probe": container.get("readinessProbe"),
        "liveness_probe": container.get("livenessProbe"),
        "startup_probe": container.get("startupProbe"),
    }

def _parse_kubernetes(document: dict) -> dict:
    kind = document.get("kind")
    metadata = document.get("metadata", {})
    spec = document.get("spec", {})

    pod_spec = None
    containers = []
    init_containers = []
    ephemeral_containers = []

    if kind == "Pod":
        pod_spec = spec

    elif kind in {"Deployment", "DaemonSet", "StatefulSet", "ReplicaSet", "Job"}:
        pod_spec = (
            spec.get("template", {})
            .get("spec", {})
        )

    elif kind == "CronJob":
        pod_spec = (
            spec.get("jobTemplate", {})
            .get("spec", {})
            .get("template", {})
            .get("spec", {})
        )

    if isinstance(pod_spec, dict):
        containers = [
            _parse_kubernetes_container(item)
            for item in pod_spec.get("containers", [])
        ]

        init_containers = [
            _parse_kubernetes_container(item)
            for item in pod_spec.get("initContainers", [])
        ]

        ephemeral_containers = [
            _parse_kubernetes_container(item)
            for item in pod_spec.get("ephemeralContainers", [])
        ]

    return {
        "kind": kind,
        "api_version": document.get("apiVersion"),
        "metadata": {
            "name": metadata.get("name"),
            "namespace": metadata.get("namespace"),
            "labels": metadata.get("labels", {}),
            "annotations": metadata.get("annotations", {}),
        },
        "replicas": spec.get("replicas"),
        "selector": spec.get("selector"),
        "pod_spec": pod_spec,
        "containers": containers,
        "init_containers": init_containers,
        "ephemeral_containers": ephemeral_containers,
        "container_count": (
            len(containers)
            + len(init_containers)
            + len(ephemeral_containers)
        ),
    }

def _parse_oci_layout(path: Path) -> dict:
    layout_path = path / "oci-layout"
    index_path = path / "index.json"

    if not layout_path.is_file() or not index_path.is_file():
        raise ValueError("Directory is not a valid OCI image layout.")

    layout = json.loads(layout_path.read_text(encoding="utf-8"))
    index = json.loads(index_path.read_text(encoding="utf-8"))

    manifests = []

    for descriptor in index.get("manifests", []):
        digest = descriptor.get("digest", "")
        algorithm, separator, value = digest.partition(":")

        if not separator or algorithm != "sha256":
            continue

        manifest_path = path / "blobs" / algorithm / value

        if not manifest_path.is_file():
            continue

        manifest = json.loads(
            manifest_path.read_text(encoding="utf-8")
        )

        manifests.append({
            "descriptor": descriptor,
            "manifest": manifest,
        })

    return {
        "format": "OCI Image Layout",
        "layout_version": layout.get("imageLayoutVersion"),
        "index": index,
        "manifests": manifests,
        "manifest_count": len(manifests),
    }

def _parse_oci_archive(path: Path) -> dict:
    manifests = []
    config_files = []
    layers = []

    with tarfile.open(path, mode="r:*") as archive:
        members = archive.getmembers()

        if len(members) > 50000:
            raise ValueError("Container archive exceeds the 50,000-entry limit.")

        for member in members:
            if not member.isfile():
                continue

            name = member.name.lstrip("./")

            if name.startswith("/") or ".." in Path(name).parts:
                continue

            if member.size > 50 * 1024 * 1024:
                continue

            extracted = archive.extractfile(member)
            if extracted is None:
                continue

            raw = extracted.read()

            if name == "manifest.json":
                manifests = json.loads(raw.decode("utf-8"))

            elif name == "index.json":
                manifests = json.loads(raw.decode("utf-8"))

            elif name == "oci-layout":
                continue

            elif name.endswith(".json") and (
                name.startswith("blobs/sha256/")
            ):
                try:
                    document = json.loads(raw.decode("utf-8"))

                    if "rootfs" in document and "config" in document:
                        config_files.append(document)

                except (json.JSONDecodeError, UnicodeDecodeError):
                    pass

            if name.startswith("blobs/sha256/") or (
                name.endswith(".tar") or name.endswith(".tar.gz")
            ):
                layers.append({
                    "name": name,
                    "size": member.size,
                })

    return {
        "format": "Container Image Archive",
        "manifests": manifests,
        "image_configurations": config_files,
        "layers": layers,
        "layer_count": len(layers),
    }

def _detect_yaml_type(documents: list) -> tuple[str, list]:
    compose = []
    kubernetes = []

    for document in documents:
        if "services" in document and isinstance(document["services"], dict):
            compose.append(document)
        elif document.get("apiVersion") and document.get("kind"):
            kubernetes.append(document)

    if compose:
        return "compose", compose

    if kubernetes:
        return "kubernetes", kubernetes

    raise ValueError(
        "YAML file is not a recognised Compose or Kubernetes manifest."
    )

def _parse_container(path: Path, raw: bytes) -> dict:
    filename = path.name.lower()

    if filename == "dockerfile" or filename.startswith("dockerfile."):
        return _parse_dockerfile(raw)

    if path.is_dir():
        return _parse_oci_layout(path)

    if filename in {
        "compose.yaml",
        "compose.yml",
        "docker-compose.yaml",
        "docker-compose.yml",
    }:
        documents = _load_yaml(raw)
        if not documents:
            raise ValueError("Compose file contains no documents.")

        return _parse_compose(documents[0])

    if filename.endswith((".yaml", ".yml")):
        documents = _load_yaml(raw)
        format_type, recognised = _detect_yaml_type(documents)

        if format_type == "compose":
            return _parse_compose(recognised[0])

        resources = [
            _parse_kubernetes(document)
            for document in recognised
        ]

        return {
            "format": "Kubernetes",
            "resources": resources,
            "resource_count": len(resources),
            "container_count": sum(
                item["container_count"] for item in resources
            ),
        }

    if filename.endswith(".json"):
        document = json.loads(raw.decode("utf-8-sig"))

        if not isinstance(document, dict):
            raise ValueError("Container JSON must contain an object.")

        if "services" in document:
            return _parse_compose(document)

        if document.get("apiVersion") and document.get("kind"):
            resource = _parse_kubernetes(document)
            return {
                "format": "Kubernetes",
                "resources": [resource],
                "resource_count": 1,
                "container_count": resource["container_count"],
            }

        if "manifests" in document and "schemaVersion" in document:
            return {
                "format": "OCI Image Manifest",
                "manifest": document,
            }

        raise ValueError("Unrecognised container JSON document.")

    if filename.endswith((".tar", ".tar.gz", ".tgz")):
        return _parse_oci_archive(path)

    raise ValueError(
        f"Unsupported container artefact: {path.name}"
    )

def containerextract(packet: Packet) -> Packet:
    result = packet.child(
        stage="extraction",
        artefact_type="container",
        status=PacketStatus.RUNNING,
    )

    try:
        source = packet.input

        if not isinstance(source, str) or not source.strip():
            raise ValueError("A container artefact path is required.")

        path = Path(source).expanduser()

        if not path.exists():
            raise FileNotFoundError(
                f"Container artefact not found: {path}"
            )

        if path.is_dir():
            extracted = _parse_oci_layout(path)
            result.data = extracted
            result.status = PacketStatus.SUCCESS
            return result

        if not path.is_file():
            raise ValueError("Container input must be a file or OCI directory.")

        raw = path.read_bytes()

        if not raw:
            raise ValueError("Container artefact is empty.")

        extracted = _parse_container(path, raw)

        extracted["source_file"] = {
            "filename": path.name,
            "path": str(path.resolve()),
            "size": len(raw),
            "hashes": _hash_file(path),
        }

        result.data = extracted
        result.status = PacketStatus.SUCCESS

    except FileNotFoundError as exc:
        result.add_error(
            code="CONTAINER_FILE_NOT_FOUND",
            message=str(exc),
            component="extractors.container",
        )
        result.status = PacketStatus.FAILED

    except PermissionError as exc:
        result.add_error(
            code="CONTAINER_PERMISSION_DENIED",
            message=str(exc),
            component="extractors.container",
        )
        result.status = PacketStatus.FAILED

    except (json.JSONDecodeError, tarfile.TarError) as exc:
        result.add_error(
            code="INVALID_CONTAINER_ARTEFACT",
            message=str(exc),
            component="extractors.container",
        )
        result.status = PacketStatus.FAILED

    except (OSError, UnicodeDecodeError, ValueError, TypeError) as exc:
        result.add_error(
            code="CONTAINER_EXTRACTION_FAILED",
            message=str(exc),
            component="extractors.container",
        )
        result.status = PacketStatus.FAILED

    except Exception as exc:
        result.add_error(
            code="UNEXPECTED_CONTAINER_ERROR",
            message=str(exc),
            component="extractors.container",
        )
        result.status = PacketStatus.FAILED

    return result