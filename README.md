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

Theseus is an OSINT collection tool that runs existing open-source intelligence tools and services from one workflow and presents their results in a consistent, readable format.

It collects and organizes. It does not score, rank, or draw conclusions. The analyst does the analysis.

---

## What it does

Investigators often move between many sites and tools, each with its own interface and output format. Theseus reduces that overhead:

```
Target
  ↓
Identify what kind of target it is
  ↓
Run the relevant collectors
  ↓
Normalize their output
  ↓
Present the results, with sources and timestamps
```

Give it a target and it identifies the type (IP, domain, URL, username, or email), queries the sources that apply to that type, and prints the results in a fixed structure so output looks the same regardless of which tool produced it.

## Design principles

- **Present, don't interpret.** Theseus reports what sources returned. It does not assign risk scores, guess intent, or attribute activity to a person or actor.
- **Keep provenance.** Every result should be traceable to the source that produced it and, where the source provides it, the time it was observed.
- **Don't reinvent tools.** Existing OSINT tools and services do the collecting. Theseus wraps them behind a common interface.
- **Stay modular.** Each source is an independent collector, so adding or replacing one does not require changing the rest.

## Status

**Early development.** Interfaces and output formats may change.

### Target types

| Target | Status | Report sections |
|---|---|---|
| IP address | Implemented | Identity, Network, Location, Exposure, Services, Web, TLS, Temporal metadata |
| Domain | Implemented | Identity, DNS, Subdomains, Certificates, Hosting/IPs, Web presence, Registration, Email infrastructure |
| URL | In progress | Final URL, Redirects, Domain/IP, Page title, Technologies, Certificates, Reputation, Historical observations |
| Username | Planned | Platform accounts, Profile URLs, Display names, Associated emails/domains, Activity indicators |
| Email | Planned | Breach exposure, Associated usernames, Associated domains, Provider, Aliases, Public appearances |

## Example output

Trimmed output for `1.1.1.1` (a well-known public address, used here for testing):

```
Target: 1.1.1.1
Type: ip_address

Identity
  IP Address: 1.1.1.1
  Organization: APNIC Research and Development
  ISP: Cloudflare, Inc.
  Hostnames:
    - one.one.one.one
    ...

Network
  ASN: 13335

Location
  Country: Australia
  Region: QLD
  City: Brisbane

Exposure
  Open Ports:
    - 53
    - 80
    - 443
    ...

TLS
  443/tcp
    Cipher: TLS_AES_256_GCM_SHA384
    Certificate Subject: cloudflare-dns.com
    Certificate Issuer: SSL.com SSL Intermediate CA ECC R2

Temporal Metadata
  443/tcp
    Observed: 2026-09-29T06:47:02.566293
```

**Reading this output correctly:** results reflect what the source reported, not verified facts. `1.1.1.1` is an anycast address served from many locations, so the geolocation above is not meaningful for it, and the hostnames listed can come from shared infrastructure rather than ownership. Theseus does not currently flag these cases, so the analyst needs to judge them.

## Scope and ethics

- Theseus is intended for lawful research and investigation using publicly available information.
- It relies on third-party sources and APIs. Users are responsible for following each service's terms of use and for holding any required API keys.
- Some collectors query data that a service has already indexed. Any collector that sends requests directly to a target (for example, following URL redirects) is documented as such.
- Reports about people (email, username lookups) can contain personal data. Handle it responsibly, collect only what an investigation needs, and follow the law and any ethical guidelines that apply to you.
- Do not use Theseus for stalking, harassment, or unauthorized access.

## Roadmap

- Complete the domain, URL, username, and email target types
- Surface related entities found in results (hostnames, domains, usernames) as **leads** the analyst can choose to investigate next, rather than following them automatically
- Flag known data-quality limits, such as anycast or CDN addresses
- Export reports (JSON, Markdown)
- Replace or supplement external integrations with purpose-built collectors over time

## Why I built it

Many excellent OSINT tools exist, but they live in different places with different interfaces. Theseus is an attempt to bring them into one workflow while keeping each tool independent. It is also a learning project: as I build individual OSINT capabilities myself, external integrations can be supplemented or replaced.

## License

MIT License