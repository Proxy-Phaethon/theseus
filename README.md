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

**Theseus is an OSINT investigation tool that brings multiple open-source intelligence tools into one workflow.**

Instead of manually searching through different websites, running separate tools, and piecing their results together, Theseus acts as an orchestrator. Give it a target, and it determines what tools and sources can be used to investigate it.

```text
Target
  ↓
Identify
  ↓
Find relevant tools
  ↓
Collect information
  ↓
Connect findings
  ↓
Present investigation
```

## Example

An investigation can start with something as simple as an email address:

```text
$ theseus investigate example@email.com
```

Theseus identifies it as an email address and can use the sources available for that type of target.

```text
example@email.com
        │
        ├── Breach information
        ├── Username associations
        ├── Public web results
        └── Other available sources
```

Those results can then lead to new entities and further investigation.

```text
example@email.com
        │
        ├── username
        │      ├── social accounts
        │      └── other references
        │
        └── domain
               ├── DNS
               ├── certificates
               └── infrastructure
```

## What it uses

Theseus is designed to work with existing OSINT tools and services rather than reinventing them.

Potential integrations include:

* SearXNG for general web search
* Have I Been Pwned and other breach intelligence services
* Maigret / Sherlock for username investigation
* DNS and RDAP services
* Certificate transparency sources
* Shodan / Censys
* URLScan
* Other OSINT tools and APIs

As the project develops, tools can be added as independent collectors.

## Why I Built It

There are a lot of excellent OSINT tools available, but they often live in completely different places and have completely different interfaces.

Theseus is an attempt to bring them together into a single investigation workflow while keeping each tool independent.

It is also a learning project. As I become capable of building individual OSINT capabilities myself, external integrations can gradually be replaced or supplemented with tools built specifically for Theseus.

## Status

**Early development**

The architecture is currently being redesigned around the investigation/collector model. APIs, collectors, data models, and the user interface are expected to change as the project develops.

## License

MIT License

note for tmrw - add next entity type.