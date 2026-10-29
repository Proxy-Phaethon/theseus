<div align="center">

<pre>
                                                  
                                                  
           ███                      ███           
         ████████                ████████         
        ██████████   ██    ██  ███████████        
       ███     ████████    ████████     ███       
       █▒█        ████      ████        █▒█       
       █▓█     ███ █          █ ███     █▓█       
       ███        █            █        ███       
       ███         ██        ██         ███       
        ███         ██      ██         ███        
           ██       ██      ██       ██           
                    ███    ███                    
                      █    █                      
                      █    █                      
                                                  
                       █  █                       
                                                  
                                                  
</pre>

</div>

<div align="center">

![Python](https://img.shields.io/badge/Python-3776AB?style=for-the-badge\&logo=python\&logoColor=white)

</div>

# Theseus

**A digital artefact extraction and intelligence platform.**

Theseus discovers, extracts, classifies, and correlates entities hidden within digital artefacts. It transforms raw digital information into structured, traceable intelligence that can be investigated further.

From email headers and browser metadata to document properties, network traffic, operating-system artefacts, and online infrastructure, Theseus provides a unified framework for extracting meaningful information from the digital world.

## Overview

Digital artefacts contain more information than their visible contents suggest. An email can expose its routing infrastructure. A document can reveal its author and creation history. A website can disclose related domains, account identifiers, external services, and embedded resources. A system log can connect accounts, devices, processes, and network activity.

Theseus is designed to extract these details systematically, identify the entities they reveal, and establish relationships between them.

Rather than requiring an investigator to begin with a known email address, domain, IP address, or username, Theseus can begin with the artefact itself.

**The artefact is the starting point. The entities it reveals are the leads.**

## Core capabilities

### Artefact extraction

Theseus processes digital artefacts across multiple formats and environments, extracting structured information from their contents and metadata.

Supported artefact categories include:

- **Web and browser:** HTTP headers, HTML, cookies, browser history, local storage, redirects, web archives, and application metadata.
- **Email and communications:** Email headers, MIME messages, attachments, SMS/MMS exports, chat records, contact cards, and call metadata.
- **Internet infrastructure:** DNS records, TLS certificates, Certificate Transparency entries, WHOIS/RDAP data, IP allocation records, routing information, and service banners.
- **Files and documents:** PDF, Office documents, images, audio, video, archives, file metadata, hashes, digital signatures, and embedded resources.
- **Operating systems:** Windows Registry and event logs, macOS system artefacts, Linux logs, filesystem metadata, execution traces, and device records.
- **Network traffic:** PCAP/PCAPNG captures, HTTP exchanges, DNS traffic, TLS handshakes, flow records, firewall logs, and network configuration.
- **Identity and authentication:** Account identifiers, usernames, credential records, cookies, API keys, tokens, certificates, and exposed secrets.
- **Social platforms:** Public profiles, posts, comments, account identifiers, linked accounts, and publicly accessible platform data.
- **Mobile devices:** Application databases, device backups, messages, contacts, call records, media metadata, and application configuration.
- **Software and repositories:** Git history, package manifests, dependency lockfiles, source code, build logs, API specifications, and infrastructure configuration.
- **Databases and structured data:** JSON, XML, YAML, CSV, SQL dumps, SQLite databases, spreadsheets, and API response archives.
- **Cloud and enterprise systems:** Audit logs, resource inventories, identity-provider records, SaaS activity, cloud configurations, and object-storage metadata.
- **Corporate and public records:** Company filings, annual reports, securities disclosures, patents, procurement records, public datasets, and organisational documents.
- **Geospatial and multimedia:** EXIF GPS data, GPX tracks, KML/KMZ, GeoJSON, OCR text, transcripts, and media fingerprints.

### Entity identification

Extracted information is normalised into consistent entity types, including:

- People and organisations
- Email addresses and telephone numbers
- Usernames and online accounts
- Domains, URLs, and IP addresses
- Physical addresses and geographic coordinates
- Files, hashes, certificates, and cryptographic fingerprints
- Device and account identifiers
- Software packages, repositories, and infrastructure resources
- Transactions, timestamps, and other domain-specific identifiers
- Credentials and other sensitive information requiring controlled handling

Theseus identifies entities regardless of which supported artefact reveals them, allowing the same entity to be recognised across different sources and formats.

### Relationship discovery

Individual findings become more useful when their relationships can be examined together.

Theseus connects extracted entities to their originating artefacts and records relationships such as:

- A document containing an email address.
- An email referencing a domain.
- A certificate listing several hostnames.
- A repository referencing an external service.
- A browser record pointing to a URL.
- A corporate filing associating a person with an organisation.
- A configuration file referencing an IP address or service.
- Multiple artefacts containing the same identifier.

Relationships retain their supporting evidence and are distinguished from assumptions or inferred associations.

### Iterative investigation

Entity extraction and investigation operate as a continuous pipeline.

1. An investigator supplies a digital artefact or supported data source.
2. Theseus identifies and parses the artefact.
3. Extracted entities are classified, normalised, and deduplicated.
4. Each entity is linked to its source and relevant contextual information.
5. Appropriate investigation modules process eligible entities.
6. New findings reveal additional entities and relationships.
7. The process continues as new leads are discovered.
8. Results are consolidated into a traceable body of intelligence.

This allows an investigation to expand beyond its initial input without requiring every subsequent entity to be identified manually.

### Investigation and enrichment

Theseus integrates specialised collectors to gather additional information about discovered entities.

Collectors are selected according to entity type and investigation context. Email addresses, domains, IP addresses, URLs, usernames, and other identifiers are routed to relevant modules rather than indiscriminately submitted to every available tool.

Collected results are normalised and associated with their sources, allowing findings from different tools to be compared and correlated.

### Evidence provenance and sensitive-data handling

Every finding retains its relationship to the artefact or source from which it originated.

Theseus records relevant acquisition details, timestamps, source locations, extraction methods, and integrity information. Direct observations are distinguished from derived values and inferred relationships.

Sensitive findings, including exposed credentials, session cookies, API keys, and authentication tokens, are recorded through a controlled evidence-handling workflow. Raw sensitive values are protected through encryption, access controls, and appropriate retention policies. Routine output redacts secrets while preserving sufficient information to identify, track, and remediate repeated exposures.

The objective is not simply to discover information, but to preserve the context necessary to evaluate it responsibly.

## Design principles

**Artefact-first discovery.** Investigations can begin with raw digital evidence rather than a predetermined entity.

**Extensibility.** New parsers, entity types, and collectors integrate through defined interfaces.

**Provenance by default.** Findings retain their source and the context in which they were discovered.

**Context-aware routing.** Entities are sent only to relevant investigation modules.

**Separation of evidence and inference.** Direct observations, transformations, and inferred relationships remain distinguishable.

**Responsible sensitive-data handling.** Exposure findings are preserved for investigation and remediation without unnecessarily exposing secrets in routine outputs.

**Reproducibility.** Extraction and investigation results retain the information needed to understand how they were obtained.

## Project goal

Theseus aims to provide a unified system for discovering entities across the digital environment, from publicly accessible online resources to local files, applications, operating systems, and network records.

Its purpose is to reduce the gap between encountering a digital artefact and understanding the information, identifiers, and relationships it contains.

**Theseus v1.0.0 establishes the artefact extractor as the foundation of the platform, with entity investigation and relationship discovery built around the information it uncovers.**

## Version

**Target release:** v1.0.0

The v1.0.0 release represents the redesigned Theseus architecture, bringing artefact extraction, entity identification, provenance tracking, investigation routing, and relationship analysis together as a cohesive system.

## Contributing

Contributions, bug reports, and suggestions are welcome. When reporting a problem, include the operating system, Python version, installation method, relevant command output, and steps needed to reproduce it. Never include private credentials or sensitive investigation data.

## Documentation

- **[Wiki](https://github.com/Proxy-Phaethon/theseus/wiki):** Detailed project documentation, technical references, and investigation-specific information.
- **[Releases](https://github.com/Proxy-Phaethon/theseus/releases):** Version history, release notes, and changes between releases.

## License

Theseus is released under the Apache License 2.0. See [LICENSE](LICENSE) for details.

<div align="center"> <pre>
░▒▓████████▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓████████▓▒░░▒▓███████▓▒░▒▓████████▓▒░▒▓█▓▒░░▒▓█▓▒░░▒▓███████▓▒░ 
   ░▒▓█▓▒░   ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░      ░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░        
   ░▒▓█▓▒░   ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░      ░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░        
   ░▒▓█▓▒░   ░▒▓████████▓▒░▒▓██████▓▒░  ░▒▓██████▓▒░░▒▓██████▓▒░ ░▒▓█▓▒░░▒▓█▓▒░░▒▓██████▓▒░  
   ░▒▓█▓▒░   ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░             ░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░      ░▒▓█▓▒░ 
   ░▒▓█▓▒░   ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░             ░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░      ░▒▓█▓▒░ 
   ░▒▓█▓▒░   ░▒▓█▓▒░░▒▓█▓▒░▒▓████████▓▒░▒▓███████▓▒░░▒▓████████▓▒░░▒▓██████▓▒░░▒▓███████▓▒░  
</pre>