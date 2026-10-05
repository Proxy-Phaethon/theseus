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

Theseus is an OSINT investigation tool that brings existing intelligence tools and services together behind a single workflow.

Give Theseus a target such as an IP address, domain, email address, username, or URL. Theseus identifies the target, selects the relevant collectors, gathers information from those sources, and organizes the results into an investigation report.

```text
Target
   ↓
Identifier
   ↓
Collectors
   ↓
Responder
   ↓
Investigation Report
```

Theseus is an **internet explorer**, not a search engine.

It does not try to replace the individual tools it uses. Instead, it provides the layer that connects them.

---

## Current Status

**Version: v0.2.0**

Theseus is being developed around an entity-based architecture.

The current release focuses heavily on IP investigations, combining network intelligence, exposure data, TLS information, reputation, threat intelligence, anonymizer detection, DNS information, and observations from multiple independent sources.

Other entity types are being expanded incrementally.

---

## Installation

Install the latest version directly from GitHub:

```bash
pip install git+https://github.com/Proxy-Phaethon/theseus.git
```

Once installed, run:

```bash
theseus
```

---

## API Keys

Some collectors require external API keys.

For example, Shodan requires:

```bash
export SHODAN_API_KEY="your-api-key"
```

On macOS, this can be added to `~/.zshrc`:

```bash
echo 'export SHODAN_API_KEY="your-api-key"' >> ~/.zshrc
source ~/.zshrc
```

Other collectors may require their own credentials.

API keys should never be committed to the repository.

---

## Usage

Start Theseus:

```bash
theseus
```

Then provide a target:

```text
> 8.8.8.8
```

Examples of other targets:

```text
> wikipedia.com

> someone@example.com

> @username

> https://example.com
```

Theseus identifies the entity type automatically and routes the target to the appropriate collectors.

Once collection begins, Theseus displays a terminal loading indicator while the collectors run.

When collection is complete, the responder organizes the collected observations into a structured investigation report.

Enter `q` to exit.

---

# Investigations

## IP Addresses

IP investigation is currently the most developed part of Theseus.

The IP collector ecosystem covers several categories of intelligence:

* Network and ASN information
* Geolocation
* Hosting and infrastructure
* Open ports and services
* TLS certificates
* Reverse DNS
* Passive DNS
* Reputation
* Threat intelligence
* Anonymizer detection
* Web information
* Internet exposure

Current collectors include:

* **Shodan**
* **Censys**
* **Netlas**
* **IPinfo**
* **ip-api**
* **ipapi.is**
* **RIPEstat**
* **Team Cymru**
* **AbuseIPDB**
* **AlienVault OTX**
* **VirusTotal**
* **Tor exit-node lists**
* **DNS and passive DNS sources**
* **tlsx**

Theseus does not blindly merge conflicting observations into a single value.

For example, if different sources report different locations:

```text
Observations

  Region mismatch:
    California (1 source)
    Virginia (1 source)

  City mismatch:
    Mountain View (1 source)
    Ashburn (1 source)
```

the disagreement remains visible in the report.

The purpose is to preserve the collected evidence rather than manufacture certainty where the sources disagree.

---

## Domains

Domain investigation is currently being expanded.

Current collectors include:

* **LDNS**
* **RDAP**

Domain collection covers information such as:

* Domain identity
* Web presence
* Redirects
* HTTP security headers
* Registrar information
* Registration dates
* Expiration dates
* Domain status
* Nameservers
* DNSSEC
* DNS records

---

## Email Addresses

Current email collectors include:

* **XposedOrNot**
* **Disify**

They provide information such as:

* Email and domain information
* Disposable email detection
* Role-account detection
* Free-provider detection
* DNS/MX information
* Known breach exposure

---

## Usernames

Current username collection uses:

* **WhatsMyName**

Theseus uses the WhatsMyName dataset to check usernames across supported websites.

Results can include:

* Website
* Category
* Detected URL
* HTTP status

---

## URLs

URL investigation currently uses:

* **HTTP**
* **DNS**

These collectors gather information about the specific URL being investigated, including:

* Requested URL
* Final URL
* Redirect chain
* HTTP status
* Content type
* Response size
* Response time
* DNS records
* A / AAAA records
* CNAME
* MX
* NS
* TXT

---

# Why Theseus?

The internet already has an enormous number of OSINT tools.

There are APIs, datasets, command-line utilities, search engines, scanners, passive DNS services, reputation databases, certificate sources, and specialized intelligence platforms.

The problem is not necessarily the lack of tools.

It is the amount of glue required to use them together.

Without Theseus, an investigation might look like:

```text
IP
 ├── Shodan
 ├── Censys
 ├── AbuseIPDB
 ├── VirusTotal
 ├── RIPEstat
 ├── ...
```

With Theseus:

```text
Target
  ↓
Theseus
  ↓
Relevant collectors
  ↓
Investigation report
```

The investigator provides the target.

Theseus handles the routing and collection.

The underlying tools remain the sources of intelligence.

---

# Roadmap

Theseus is being developed incrementally.

Current development focuses on expanding the collector ecosystem and improving the investigation responders for each supported entity type.

Planned areas include:

* More OSINT collectors
* More entity types
* More cross-source correlation
* Improved investigation reports
* Better collector error handling
* Concurrent collection
* Collector configuration
* Expanded local-tool integration
* Improved CLI experience

The goal is to make Theseus capable of navigating an investigation across many existing intelligence sources without requiring the investigator to manually operate each one.

---

# License

MIT License