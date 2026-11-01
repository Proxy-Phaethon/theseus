import hashlib
import re
import xml.etree.ElementTree as ET

from pathlib import Path
from collections import Counter

from core.packets import Packet, PacketStatus

def xmlextract(packet):
    result = packet.child(
        stage="extraction",
        artefact_type="xml",
        status=PacketStatus.RUNNING,
    )

    try:
        source = packet.input

        if not isinstance(source, (str, Path)):
            raise ValueError("Input must be an XML string or file path.")

        path = Path(source)
        source_type = "raw"
        source_path = None
        file_size = None

        if path.is_file():
            raw_bytes = path.read_bytes()
            raw = raw_bytes.decode("utf-8-sig")
            source_type = "file"
            source_path = str(path.resolve())
            file_size = len(raw_bytes)
            source_hash = hashlib.sha256(raw_bytes).hexdigest()
        else:
            raw = str(source)

            if not raw.strip():
                raise ValueError("XML input is empty.")

            source_hash = hashlib.sha256(
                raw.encode("utf-8")
            ).hexdigest()

        if not raw.strip():
            raise ValueError("XML input is empty.")

        if re.search(
            r"<!\s*(DOCTYPE|ENTITY)\b",
            raw,
            flags=re.IGNORECASE,
        ):
            raise ValueError(
                "DTD and entity declarations are not supported."
            )

        parser = ET.XMLParser(
            target=ET.TreeBuilder(
                insert_comments=True,
                insert_pis=True,
            )
        )

        root = ET.fromstring(raw, parser=parser)

        statistics = {
            "elements": 0,
            "attributes": 0,
            "text_nodes": 0,
            "comments": 0,
            "processing_instructions": 0,
            "namespaces": 0,
        }

        element_names = Counter()
        attribute_names = Counter()
        namespace_names = set()
        elements = []
        comments = []
        processing_instructions = []
        max_depth = 0

        def split_name(name):
            if not isinstance(name, str):
                return {
                    "name": None,
                    "namespace": None,
                    "local_name": None,
                }

            if name.startswith("{") and "}" in name:
                namespace, local_name = name[1:].split("}", 1)

                return {
                    "name": name,
                    "namespace": namespace,
                    "local_name": local_name,
                }

            return {
                "name": name,
                "namespace": None,
                "local_name": name,
            }

        def inspect(element, depth=0, parent=None):
            nonlocal max_depth

            max_depth = max(max_depth, depth)

            if element.tag is ET.Comment:
                statistics["comments"] += 1
                comments.append({
                    "text": element.text,
                    "parent": parent,
                })
                return

            if element.tag is ET.ProcessingInstruction:
                statistics["processing_instructions"] += 1
                processing_instructions.append({
                    "text": element.text,
                    "parent": parent,
                })
                return

            name_info = split_name(element.tag)
            element_names[element.tag] += 1

            if name_info["namespace"]:
                namespace_names.add(name_info["namespace"])

            attributes = {}

            for key, value in element.attrib.items():
                attributes[key] = value
                attribute_names[key] += 1
                statistics["attributes"] += 1

                attribute_info = split_name(key)

                if attribute_info["namespace"]:
                    namespace_names.add(
                        attribute_info["namespace"]
                    )

            if element.text and element.text.strip():
                statistics["text_nodes"] += 1

            entry = {
                **name_info,
                "attributes": attributes,
                "text": element.text,
                "tail": element.tail,
                "depth": depth,
                "children": [],
            }

            elements.append(entry)
            statistics["elements"] += 1

            for child in element:
                child_entry = inspect(
                    child,
                    depth + 1,
                    element.tag,
                )

                if child_entry is not None:
                    entry["children"].append(child_entry)

            return entry

        document = inspect(root)

        statistics["namespaces"] = len(namespace_names)

        result.data = {
            "source": {
                "type": source_type,
                "path": source_path,
                "size": file_size,
                "sha256": source_hash,
            },
            "xml": {
                "root": document,
                "root_element": root.tag,
                "statistics": statistics,
                "max_depth": max_depth,
                "element_names": dict(element_names),
                "attribute_names": dict(attribute_names),
                "namespaces": sorted(namespace_names),
                "comments": comments,
                "processing_instructions": processing_instructions,
            },
        }

        result.status = PacketStatus.SUCCESS

    except FileNotFoundError:
        result.status = PacketStatus.FAILED
        result.add_error(
            code="XML_FILE_NOT_FOUND",
            message="The specified XML file could not be found.",
            component="extractors.xml",
        )

    except PermissionError:
        result.status = PacketStatus.FAILED
        result.add_error(
            code="XML_PERMISSION_DENIED",
            message="Permission denied while reading the XML file.",
            component="extractors.xml",
        )

    except ET.ParseError as exc:
        result.status = PacketStatus.FAILED
        result.add_error(
            code="INVALID_XML",
            message=str(exc),
            component="extractors.xml",
        )

    except (OSError, ValueError, TypeError, UnicodeDecodeError) as exc:
        result.status = PacketStatus.FAILED
        result.add_error(
            code="XML_EXTRACTION_FAILED",
            message=str(exc),
            component="extractors.xml",
        )

    except Exception as exc:
        result.status = PacketStatus.FAILED
        result.add_error(
            code="UNEXPECTED_ERROR",
            message=str(exc),
            component="extractors.xml",
        )

    return result