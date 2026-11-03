from rich.theme import Theme

THESEUS_THEME = Theme(
    {
        # Primary palette
        "accent": "#D6AD45",
        "heading": "bold white",
        "text": "white",
        "muted": "#777777",
        "dim": "#555555",
        "border": "#444444",

        # Operational states
        "success": "#398CCB",
        "error": "#D94A4A",
        "warning": "#D6AD45",

        # Terminal elements
        "prompt": "bold #D6AD45",
        "command": "white",
        "section": "bold #D6AD45",
        "label": "#AAAAAA",
        "value": "white",
        "metadata": "#777777",

        # Investigation records
        "case.reference": "bold #D6AD45",
        "case.heading": "bold white",
        "case.separator": "#555555",
    }
)