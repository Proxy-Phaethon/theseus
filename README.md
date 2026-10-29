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

flowchart TD
    A["main.py<br/>Receive user input"] --> B["core/packets.py<br/>Create initial packet"]
    B --> C["core/identifier.py<br/>Identify and classify artefacts"]
    C --> D["core/registry.py<br/>Access registered extractors"]
    D --> E["core/executor.py<br/>Scope tasks and route inputs"]

    E --> F["Create child task packets<br/>Shared request_id, unique task_id"]
    
    F --> G["Select relevant extractors"]
    G --> H1["extractors/webandbrowser/"]
    G --> H2["extractors/emailandmessages/"]
    G --> H3["extractors/networkandinfrastructure/"]
    G --> H4["Other extractor categories"]

    H1 --> I["Return standard result packets"]
    H2 --> I
    H3 --> I
    H4 --> I

    I --> J["core/responder.py<br/>Aggregate and correlate results"]
    J --> K["Process shared envelope fields"]
    K --> L["Interpret extractor-specific data"]
    L --> M["Build final investigation response"]
    M --> N["main.py<br/>Display through existing UI"]

    J -. "Discoveries may create new tasks" .-> E

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