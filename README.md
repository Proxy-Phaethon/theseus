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

# Theseus

**Explore the internet. Follow the evidence. Connect the dots.**

Theseus is an extensible OSINT investigation tool designed to explore publicly available information, investigate digital targets, and organize findings into structured reports.

Give Theseus a target, and it investigates the information associated with it using a growing collection of intelligence-gathering capabilities. Its own tools and integrations with existing services work together within a unified investigation environment, helping investigators move from an initial lead toward a more coherent picture.

Theseus is an **internet explorer**, not a search engine. It is built to investigate, not merely retrieve: examining digital footprints, uncovering connections, and organizing evidence that can support further investigation.

---

## Current Status

**Version: v0.7.0**

Theseus is undergoing active development ahead of its planned v1.0.0 release.

The current version introduces a redesigned collector architecture and a refreshed terminal interface. The new investigation framework is being established with email investigations as its first implemented workflow.

Other investigation types are planned for subsequent development and are not currently available through the new pipeline.

The goal for v1.0.0 is a stable, usable release with working investigation workflows, integrated tools, and consistent reporting.

## Features

- **Unified investigations:** Gather findings from multiple intelligence sources through one interface.
- **Structured reports:** Present collected information in organized sections rather than disconnected tool outputs.
- **Extensible architecture:** Add new investigation capabilities and intelligence sources as the project grows.
- **Resilient collection:** Preserve useful results when individual collectors encounter errors or unavailable sources.
- **Interactive terminal:** Investigate targets through a purpose-built CLI with progress indicators and readable output.
- **Evidence-conscious reporting:** Distinguish observations, inconclusive results, and collection failures rather than treating them as interchangeable.

## Current Capabilities

### Email investigations

The current implementation supports email-address investigations, examining several aspects of an address and its associated domain.

Depending on the information available, reports can include:

- Address normalization and syntax validation
- Domain information and mail infrastructure
- Email security configuration, including SPF and DMARC
- Breach-related observations
- Associated online services and available profile information
- Investigation status and collector errors

Results depend on the coverage and availability of the integrated tools. A missing record is not proof that information does not exist, and an account association is not definitive proof of identity.

### In development

IP addresses, domains, usernames, and URLs are part of the broader project scope. Their previous collector implementations have been removed during the architectural transition and have not yet been restored to the new pipeline.

Theseus is being developed incrementally, with functionality documented as it becomes available.

## Getting Started

Clone the repository and install Theseus in a Python virtual environment:

```bash
git clone https://github.com/Proxy-Phaethon/theseus.git
cd theseus

python -m venv .venv
source .venv/bin/activate

python -m pip install -e .
```

Launch Theseus:

```bash
theseus
```

Alternatively, run it directly from the project directory:

```bash
python main.py
```

Enter an email address at the prompt to begin an investigation.

```text
> someone@example.com
```

Use `help` to view available commands. Enter `q` to exit.

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