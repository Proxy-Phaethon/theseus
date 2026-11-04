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

**Digital Artefact Discovery & Extraction**

Theseus is a modular digital artefact extraction tool designed to identify, extract, and organise information exposed by digital assets.

Starting with an input such as a domain, subdomain, or URL, Theseus identifies the relevant artefact types and dispatches specialised extraction modules to retrieve associated information. Extracted values are organised into structured findings, with their provenance preserved and related entities identified where explicitly observed.

The result is a collection of verifiable data points that can serve as starting points for further discovery.

> The artefact is the starting point. Every extracted artefact is another lead.

## Features

- **Artefact identification:** Identifies supported input types and determines which extraction modules are applicable.
- **Modular extraction:** Runs specialised modules according to the identified artefacts.
- **Entity discovery:** Extracts identifiable values such as IP addresses, hostnames, email addresses, and other digital entities.
- **Structured findings:** Organises extracted information into consistent output formats.
- **Provenance tracking:** Preserves the source of extracted information.
- **Related entities:** Records explicitly observed associations between entities.
- **Further discovery:** Surfaces extracted artefacts that can be used as inputs for subsequent scans.
- **JSON export:** Exports the complete extraction response, including module data and supporting metadata.

## Extraction Modules

Theseus includes nine specialised extraction modules:

| Module | Purpose |
|---|---|
| Identity | Retrieves domain registration and ownership information. |
| Geography | Identifies geographical information associated with digital assets. |
| Network | Retrieves IP addresses, network ownership, and related infrastructure information. |
| Hostnames | Discovers associated hostnames and subdomains. |
| Certificate Transparency | Retrieves information from SSL/TLS certificate records. |
| Email | Extracts email addresses and associated information. |
| Website | Retrieves information from website content and HTTP responses. |
| Historical | Retrieves historical records associated with digital assets. |
| Technical | Identifies exposed services, open ports, server information, and available technical indicators. |

Each module operates independently and returns its findings through a shared response structure.

## How It Works

Theseus follows a modular extraction pipeline:

1. **Input:** Receives a digital artefact, such as a domain, subdomain, or URL.
2. **Identification:** Determines the artefact type and identifies compatible extraction modules.
3. **Execution:** Dispatches the relevant requests to specialised modules.
4. **Extraction:** Modules retrieve information and return structured results.
5. **Consolidation:** Findings are collected, organised, and presented in a unified report.
6. **Discovery:** Extracted entities are surfaced as potential inputs for further scans.

## Output

Theseus produces a consolidated report containing:

- Identification information
- Geographical findings
- Network information
- Digital identities
- Infrastructure records
- Historical observations
- Technical findings
- Investigation leads
- Supporting data

Empty sections are omitted from the readable report. Large result sets may be shortened for terminal display, with additional entries indicated in the output.

The complete extraction response remains available through JSON export. This includes individual module envelopes, extracted data, provenance, related entities, statuses, and errors.

## Installation

**Requirements**

- Python 3.10 or later

Clone the repository and install the project dependencies:

```bash
git clone https://github.com/Proxy-Phaethon/theseus.git
cd theseus
pip install .
```

## Usage

Launch Theseus:

```bash
theseus
```

Alternatively:

```bash
python main.py
```

Enter a supported target when prompted.

For example:

```text
github.com
```

Theseus identifies the input, executes the compatible extraction modules, and displays the consolidated findings.

## JSON Export

Theseus supports exporting the complete extraction response as JSON.

Exports preserve the underlying module results rather than only the information displayed in the terminal report. This allows the extracted data to be retained and examined independently of the terminal presentation.

## Design Principles

**Modularity**

Each extraction module is independent. New extraction capabilities can be introduced without redesigning the shared execution and response framework.

**Consistency**

All modules use a common response structure, keeping extracted information predictable and compatible across the system.

**Provenance**

Extracted information retains its source context. Findings should remain traceable to the module and artefact from which they originated.

**Explicit relationships**

Theseus records relationships supported by observed information. It does not present inferred associations as established facts.

**Extraction over interpretation**

Theseus retrieves, organises, and presents information. It does not attempt to determine the significance of findings or make investigative conclusions on behalf of the user.

## Project Status

**Version 1.0.0**

Theseus v1.0.0 establishes the modular extraction framework, shared response structure, specialised extraction modules, and unified reporting system.

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