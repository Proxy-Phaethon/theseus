<div align="center"> <pre> 
░▒▓████████▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓████████▓▒░░▒▓███████▓▒░▒▓████████▓▒░▒▓█▓▒░░▒▓█▓▒░░▒▓███████▓▒░ 
   ░▒▓█▓▒░   ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░      ░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░        
   ░▒▓█▓▒░   ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░      ░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░        
   ░▒▓█▓▒░   ░▒▓████████▓▒░▒▓██████▓▒░  ░▒▓██████▓▒░░▒▓██████▓▒░ ░▒▓█▓▒░░▒▓█▓▒░░▒▓██████▓▒░  
   ░▒▓█▓▒░   ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░             ░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░      ░▒▓█▓▒░ 
   ░▒▓█▓▒░   ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░             ░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░      ░▒▓█▓▒░ 
   ░▒▓█▓▒░   ░▒▓█▓▒░░▒▓█▓▒░▒▓████████▓▒░▒▓███████▓▒░░▒▓████████▓▒░░▒▓██████▓▒░░▒▓███████▓▒░  
</pre>

</div>

<div align="center">

![Python](https://img.shields.io/badge/Python-3776AB?style=for-the-badge\&logo=python\&logoColor=white)

</div>

# Theseus

Theseus is an open-source OSINT system designed to discover, collect, connect, evaluate, and explain publicly available information.

The project is developed incrementally. Each release introduces a distinct investigative capability, with the goal of building a complete OSINT workflow by version `1.0.0`.

## Roadmap

### 0.1.0 — Search [In Progress]

The foundation of Theseus.

Theseus can interpret a search query and find useful sources on the open web.

For example:

```text
search guava origin
```

The goal is not simply to return search results, but to identify sources that can answer the user's query.

---

### 0.2.0 — Retrieval & Scraping

Theseus can retrieve information from discovered sources.

Initial source types:

* Web pages
* PDF documents

The system moves from finding information to actually collecting it.

---

### 0.3.0 — Entity Extraction

Theseus identifies entities within collected information.

Examples include:

* People
* Organizations
* Locations
* Dates
* Other relevant identifiers

---

### 0.4.0 — Relationship Identification

Theseus identifies relationships between entities.

For example:

```text
Person
  ↓
works for
  ↓
Organization
```

or:

```text
Organization
  ↓
located in
  ↓
Location
```

---

### 0.5.0 — Correlation

Theseus connects information across different sources.

The system can identify when separate pieces of information may refer to the same entity, event, relationship, or activity.

---

### 0.6.0 — Provenance

Theseus tracks where information came from.

Collected information, extracted entities, relationships, and claims retain their connection to their originating sources.

The goal is to make the investigative trail recoverable rather than treating extracted information as detached facts.

---

### 0.7.0 — Source Comparison & Confidence

Theseus evaluates information across sources.

Capabilities include:

* Comparing sources
* Ranking evidence
* Identifying conflicting information
* Weighing confidence
* Distinguishing stronger evidence from weaker evidence

---

### 0.8.0 — Internal Database & Search

Theseus develops its own internal information store.

Collected entities, relationships, sources, evidence, and investigations can be retained and searched internally.

This allows an investigation to build upon information that Theseus has already discovered.

---

### 0.9.0 — Professional Answering System

Theseus turns collected and evaluated information into coherent investigative answers.

Rather than simply returning sources or isolated facts, the system can explain findings while preserving the evidence supporting them.

---

### 1.0.0 — Complete OSINT System

Theseus becomes a complete, robust search and investigation system.

This stage focuses on:

* Comprehensive error handling
* Reliable search workflows
* Robust operation
* Integration of the preceding capabilities
* Refinement of the complete investigative process

The objective is a system capable of moving from an initial question to a sourced, connected, evaluated, and clearly presented body of intelligence.

## The Progression

```text
Search
  ↓
Retrieve
  ↓
Extract
  ↓
Identify relationships
  ↓
Correlate
  ↓
Trace provenance
  ↓
Evaluate evidence
  ↓
Store knowledge
  ↓
Explain findings
  ↓
Version 1 of Theseus
```