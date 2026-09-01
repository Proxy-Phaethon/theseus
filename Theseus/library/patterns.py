# intent patterns

patterns = {

    # Conversation
    ("greeting",): "greeting",

    # Research
    ("research",): "research",
    ("research", "question"): "research_question",

    # Search / retrieval
    ("search",): "search",
    ("search", "web"): "web_search",
    ("search", "source"): "source_search",
    ("search", "paper"): "paper_search",
    ("retrieve",): "retrieve",
    ("retrieve", "source"): "source_retrieval",
    ("retrieve", "document"): "document_retrieval",

    # Sources
    ("source",): "source",
    ("paper",): "paper",
    ("article",): "article",
    ("reference",): "reference",

    # Analysis
    ("analysis",): "analyze",
    ("analysis", "data"): "analyze_data",
    ("analysis", "source"): "analyze_source",
    ("analysis", "paper"): "analyze_paper",

    # Comparison
    ("comparison",): "compare",
    ("comparison", "source"): "compare_sources",
    ("comparison", "paper"): "compare_papers",
    ("comparison", "data"): "compare_data",

    # Summarization
    ("summary",): "summarize",
    ("summary", "document"): "summarize_document",
    ("summary", "paper"): "summarize_paper",
    ("summary", "source"): "summarize_source",

    # Explanation
    ("explanation",): "explain",
    ("explanation", "concept"): "explain_concept",
    ("definition",): "define",
    ("description",): "describe",

    # Documents
    ("document",): "document",
    ("file",): "file",
    ("document", "create"): "create_document",
    ("document", "edit"): "edit_document",
    ("document", "update"): "update_document",
    ("document", "rewrite"): "rewrite_document",

    # Writing
    ("write",): "write",
    ("draft",): "draft",
    ("create",): "create",
    ("edit",): "edit",
    ("rewrite",): "rewrite",

    # Computation
    ("calculate",): "calculate",
    ("calculate", "equation"): "solve_equation",
    ("solve",): "solve",
    ("formula",): "formula",

    # Code
    ("code",): "code",
    ("execute",): "execute",
    ("compile",): "compile",
    ("test",): "test",
    ("debug",): "debug",

    # Web
    ("web",): "web",
    ("website",): "website",
    ("web", "website"): "inspect_website",

}