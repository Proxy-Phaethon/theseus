from __future__ import annotations

import esprima

from core.packets import Packet, PacketStatus

def javascriptextract(packet: Packet) -> Packet:
    """Extract structural information from JavaScript source code."""

    result = packet.child(
        stage="extraction",
        artefact_type="javascript",
        status=PacketStatus.RUNNING,
    )

    try:
        if not isinstance(packet.input, str):
            raise ValueError("JavaScript input must be a source-code string.")

        source = packet.input

        if not source.strip():
            raise ValueError("JavaScript source cannot be empty.")

        try:
            tree = esprima.parseScript(
                source,
                options={
                    "loc": True,
                    "range": True,
                    "comment": True,
                    "tolerant": False,
                },
            )
        except Exception:
            tree = esprima.parseModule(
                source,
                options={
                    "loc": True,
                    "range": True,
                    "comment": True,
                    "tolerant": False,
                },
            )

        functions = []
        classes = []
        variables = []
        imports = []
        exports = []
        references = []

        def walk(node):
            if isinstance(node, list):
                for item in node:
                    walk(item)
                return

            if not hasattr(node, "type"):
                return

            node_type = node.type
            loc = getattr(node, "loc", None)

            line = loc.start.line if loc else None

            if node_type == "FunctionDeclaration":
                functions.append({
                    "name": node.id.name if node.id else None,
                    "async": node.async_,
                    "generator": node.generator,
                    "line": line,
                })

            elif node_type == "FunctionExpression":
                functions.append({
                    "name": node.id.name if node.id else None,
                    "async": node.async_,
                    "generator": node.generator,
                    "line": line,
                })

            elif node_type == "ArrowFunctionExpression":
                functions.append({
                    "name": None,
                    "async": node.async_,
                    "generator": False,
                    "line": line,
                })

            elif node_type == "ClassDeclaration":
                classes.append({
                    "name": node.id.name if node.id else None,
                    "line": line,
                })

            elif node_type == "VariableDeclarator":
                if node.id.type == "Identifier":
                    variables.append({
                        "name": node.id.name,
                        "line": line,
                    })

            elif node_type == "ImportDeclaration":
                imports.append({
                    "source": node.source.value,
                    "line": line,
                })

            elif node_type == "ExportNamedDeclaration":
                exports.append({
                    "type": "named",
                    "line": line,
                })

            elif node_type == "ExportDefaultDeclaration":
                exports.append({
                    "type": "default",
                    "line": line,
                })

            elif node_type == "Literal":
                if isinstance(node.value, str):
                    value = node.value

                    if value.startswith(("http://", "https://")):
                        references.append(value)

            for key, value in vars(node).items():
                if key not in {"type", "loc", "range"}:
                    walk(value)

        walk(tree)

        comments = [
            {
                "type": comment.type,
                "value": comment.value.strip(),
                "line": (
                    comment.loc.start.line
                    if getattr(comment, "loc", None)
                    else None
                ),
            }
            for comment in getattr(tree, "comments", [])
        ]

        result.data = {
            "source_length": len(source),
            "line_count": len(source.splitlines()),
            "functions": functions,
            "classes": classes,
            "variables": variables,
            "imports": imports,
            "exports": exports,
            "comments": comments,
            "url_references": list(dict.fromkeys(references)),
            "counts": {
                "functions": len(functions),
                "classes": len(classes),
                "variables": len(variables),
                "imports": len(imports),
                "exports": len(exports),
                "comments": len(comments),
                "url_references": len(set(references)),
            },
        }

        result.status = PacketStatus.SUCCESS

    except Exception as exc:
        result.status = PacketStatus.FAILED
        result.add_error(
            code="javascript_extraction_failed",
            message=str(exc),
            component="extractors.javascript",
        )

    return result