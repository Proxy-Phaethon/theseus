from __future__ import annotations

from pathlib import Path

import tinycss2

from core.packets import Packet, PacketStatus

def cssextract(packet: Packet) -> Packet:
    """Extract structured information from CSS source code."""

    result = packet.child(
        stage="extraction",
        artefact_type="css",
        status=PacketStatus.RUNNING,
    )

    try:
        if not isinstance(packet.input, str):
            raise ValueError(
                "CSS input must be source code or a file path."
            )

        source_input = packet.input.strip()

        if not source_input:
            raise ValueError("CSS source cannot be empty.")

        input_path = Path(source_input)

        if input_path.is_file():
            source = input_path.read_text(
                encoding="utf-8",
                errors="replace",
            )
            source_type = "file"

        elif (
            input_path.suffix.lower() == ".css"
            or "/" in source_input
        ):
            raise FileNotFoundError(
                f"CSS file does not exist: {source_input}"
            )

        else:
            source = source_input
            source_type = "source"

        if not source.strip():
            raise ValueError("CSS source cannot be empty.")

        rules = tinycss2.parse_stylesheet(
            source,
            skip_comments=False,
            skip_whitespace=True,
        )

        selectors = []
        declarations = []
        at_rules = []
        comments = []
        imports = []
        urls = []
        fonts = []

        def extract_declarations(content, selector=None):
            parsed = tinycss2.parse_declaration_list(
                content,
                skip_comments=False,
                skip_whitespace=True,
            )

            for item in parsed:
                if item.type == "declaration":
                    entry = {
                        "property": item.name,
                        "value": tinycss2.serialize(
                            item.value
                        ).strip(),
                        "important": item.important,
                        "selector": selector,
                    }

                    declarations.append(entry)

                    if item.name.lower() == "font-family":
                        fonts.append(entry["value"])

                elif item.type == "comment":
                    comments.append(item.value.strip())

                elif item.type == "error":
                    raise ValueError(
                        "CSS declaration parsing error: "
                        f"{item.message}"
                    )

        def extract_rules(parsed_rules):
            for rule in parsed_rules:

                if rule.type == "qualified-rule":
                    selector = tinycss2.serialize(
                        rule.prelude
                    ).strip()

                    selectors.append(selector)

                    extract_declarations(
                        rule.content,
                        selector=selector,
                    )

                elif rule.type == "at-rule":
                    name = rule.lower_at_keyword
                    prelude = tinycss2.serialize(
                        rule.prelude
                    ).strip()

                    at_rules.append({
                        "name": name,
                        "prelude": prelude or None,
                        "has_block": rule.content is not None,
                    })

                    if name == "import":
                        imports.append(prelude)

                    if rule.content is not None:
                        nested_rules = tinycss2.parse_rule_list(
                            rule.content,
                            skip_comments=False,
                            skip_whitespace=True,
                        )

                        extract_rules(nested_rules)

                elif rule.type == "comment":
                    comments.append(rule.value.strip())

                elif rule.type == "error":
                    raise ValueError(
                        f"CSS parsing error: {rule.message}"
                    )

        extract_rules(rules)

        tokens = tinycss2.parse_component_value_list(source)

        def walk_tokens(items):
            for token in items:
                if token.type == "url":
                    urls.append(token.value)

                elif token.type == "function":
                    if token.lower_name == "url":
                        urls.append(
                            tinycss2.serialize(
                                token.arguments
                            ).strip(" \t\n\r\"'")
                        )

                    walk_tokens(token.arguments)

                elif token.type in {
                    "{} block",
                    "[] block",
                    "() block",
                }:
                    walk_tokens(token.content)

        walk_tokens(tokens)

        result.data = {
            "source_type": source_type,
            "source_length": len(source),
            "line_count": len(source.splitlines()),
            "selectors": selectors,
            "declarations": declarations,
            "at_rules": at_rules,
            "imports": imports,
            "urls": list(dict.fromkeys(urls)),
            "font_families": list(dict.fromkeys(fonts)),
            "comments": comments,
            "counts": {
                "selectors": len(selectors),
                "declarations": len(declarations),
                "at_rules": len(at_rules),
                "imports": len(imports),
                "urls": len(set(urls)),
                "font_families": len(set(fonts)),
                "comments": len(comments),
            },
        }

        result.status = PacketStatus.SUCCESS

    except Exception as exc:
        result.status = PacketStatus.FAILED
        result.add_error(
            code="css_extraction_failed",
            message=str(exc),
            component="extractors.css",
        )

    return result