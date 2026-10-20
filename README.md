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

It does not attempt to replace the individual tools it uses. Instead, it provides the layer that connects them, routes targets to relevant collectors, and organizes their findings into a structured report.

---

## Current Status

**Version: v0.5.0**

Theseus uses an entity-based architecture. The identifier determines the target type, the collector registry selects the relevant tools, and the responder organizes their results into an investigation report.

The current implementation supports investigations involving:

- IP addresses
- Domains
- Email addresses
- Usernames
- URLs

IP and domain investigations cover infrastructure, exposure, registration, DNS, and related intelligence. Email investigation combines email validation, breach exposure, account discovery, and public code activity. Username investigation searches supported websites for potential profiles, while URL investigation examines HTTP responses, redirects, and associated DNS information.

The collector ecosystem is designed to be extensible, allowing additional tools and entity-specific capabilities to be integrated over time.

---

## Installation

Install Theseus directly from GitHub:

```bash
pip install git+https://github.com/Proxy-Phaethon/theseus.git
```

Once installed, run:

```bash
theseus
```

## API Keys and Configuration

Some collectors require external API keys or credentials.

For example, Shodan requires:

```bash
export SHODAN_API_KEY="your-api-key"
```

On macOS, this can be added to `~/.zshrc`:

```bash
echo 'export SHODAN_API_KEY="your-api-key"' >> ~/.zshrc
source ~/.zshrc
```

Other collectors may require their own credentials or configuration.

API keys should never be committed to the repository. Consult the documentation for each integrated tool to determine its configuration requirements.

---

## Usage

Start Theseus:

```bash
theseus
```

Provide a target:

```text
> 8.8.8.8
```

Other examples:

```text
> wikipedia.com

> someone@example.com

> @username

> https://example.com
```

Theseus identifies the entity type automatically and routes the target to the appropriate collectors.

During collection, Theseus displays a terminal loading indicator while the collectors run. When collection is complete, the responder organizes the collected observations into a structured investigation report.

Enter `q` to exit.

---

# Investigations

## IP Addresses

IP investigation is one of the most developed parts of Theseus. It combines network intelligence, infrastructure observations, reputation data, and internet exposure information from multiple independent sources.

The IP collector ecosystem covers the following categories:

- Network and ASN information
- Geolocation
- Hosting and infrastructure
- Open ports and services
- TLS certificates
- Reverse DNS
- Passive DNS
- Reputation
- Threat intelligence
- Anonymizer detection
- Web information
- Internet exposure

Current collectors include:

- **Shodan**
- **Censys**
- **Netlas**
- **IPinfo**
- **ip-api**
- **ipapi.is**
- **RIPEstat**
- **Team Cymru**
- **AbuseIPDB**
- **AlienVault OTX**
- **VirusTotal**
- **Tor exit-node lists**
- **X4BNet**
- **Robtex**
- **tlsx**

Theseus organizes the collected observations into relevant sections of the IP investigation report.

It does not blindly merge conflicting observations into a single value.

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

The purpose is to preserve collected evidence rather than manufacture certainty where the sources disagree.

## Domains

Domain investigation expands Theseus beyond individual IP addresses to examine domain infrastructure, registration, related assets, and potential exposure.

The domain collector ecosystem covers:

- **WHOIS and RDAP:** Registration details, registrar information, dates, and domain status
- **DNS:** Records, nameservers, and related infrastructure
- **Subdomains:** Discovery of additional assets associated with a domain
- **Email posture:** DNS-based email infrastructure and security configuration, including SPF and DMARC checks
- **Certificates and threat intelligence:** Domain-related certificate and reputation observations
- **Hosting and IPs:** Infrastructure associated with the target domain

Current collectors include:

- **LDNS**
- **RDAP**
- **WHOIS**
- **Assetfinder**
- **Subfinder**
- **dig**
- **dnsx**
- **CheckDMARC**
- **VirusTotal**

Theseus combines observations from multiple sources into a consolidated domain investigation report rather than presenting a disconnected list of tool outputs.

The goal is to make it easier to investigate a domain's infrastructure, discover related assets, understand its security posture, and identify potential avenues for further investigation.

## Email Addresses

Email investigation examines the target address itself, its exposure in known breaches, its possible presence on online services, and publicly visible activity associated with the address.

The email responder organizes findings into four main areas.

### Email identity

Email validation and domain-level information currently use **Disify**.

Collected information can include:

- Email address and domain
- Top-level domain
- Format validation
- Disposable email detection
- Role-account detection
- Free-provider detection
- DNS availability

### Email infrastructure

Where available, Theseus reports the target domain's mail exchange (MX) records. These records identify the mail servers associated with receiving email for the domain.

### Breach exposure

**XposedOrNot** provides breach-related observations associated with the email address.

The responder summarizes the names of identified breaches, making it easier to see whether the address appears in known breach datasets.

Breach findings indicate exposure in reported datasets. They do not, by themselves, establish that an account is currently compromised.

### Account discovery

Theseus combines results from **User Scanner** and **Holehe** to identify services that may be associated with an email address.

User Scanner can provide additional information when available, including:

- Service and category
- Website URL
- Username or login
- Public profile URL
- Account identifier
- Account type
- Matching method
- Profile image URL

Holehe complements these findings with account-registration checks across supported services. Where both tools report the same service, Theseus can consolidate the findings.

Some checks may be skipped because they would trigger a password-reset email or another notification. Other checks may fail because of rate limits, access restrictions, or unexpected responses. These inconclusive results are reported separately and are not treated as proof that an account does not exist.

### Public code footprint

The **GitHub** collector searches public commit metadata for the target email address.

The responder can report:

- Matching commit count
- Associated GitHub accounts
- Commit author or committer identities

This can help connect an email address with publicly visible development activity. Search counts and commit identities are observations, not definitive proof of account ownership or personal identity.

### Email collectors

Current email collectors include:

- **Disify**
- **XposedOrNot**
- **User Scanner**
- **Holehe**
- **GitHub**

The responder consolidates their findings into a single report while retaining useful distinctions between validation, breach exposure, account discovery, and public code activity.

## Usernames

Username investigation brings together multiple account-discovery tools to search supported websites for potential profiles associated with a target username.

Current collectors include:

- **WhatsMyName**
- **User Scanner**
- **Maigret**
- **Sherlock**
- **Enola**

These tools use different datasets and detection methods. Running them together expands coverage beyond what a single username checker can provide.

### Investigation results

Depending on the collector and the information available, results can include:

- Website or service name
- Category
- Profile URL
- Username and account identifiers
- Public profile details
- Other useful account metadata

The username responder combines findings from the collectors into a consolidated report. It filters internal collection metadata, removes unnecessary HTTP status and response-time fields, and merges duplicate records when their normalized profile URLs match.

URL normalization also handles selected common variations, such as `www` prefixes, trailing slashes, and known domain aliases.

Different URLs are not automatically treated as the same account simply because they contain the same username or mention the same service.

### Interpreting results

Username discovery produces leads for further investigation, not confirmed identities.

A result may be a false positive, an unrelated profile, or a page that does not actually represent an account. Some services may also block automated checks or return incomplete information.

Each candidate profile should be verified independently before drawing conclusions about ownership or linking accounts to a person.

## URLs

URL investigation gathers HTTP and DNS observations about the specific URL being investigated.

Collected observations can include:

- Requested URL
- Final URL
- Redirect chain
- HTTP status
- Content type
- Response size
- Response time
- DNS records
- A and AAAA records
- CNAME records
- MX records
- NS records
- TXT records

These observations provide a starting point for understanding how a URL resolves and responds, along with the infrastructure associated with it.

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
 └── ...
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

Theseus handles identification, routing, collection, and presentation.

The underlying tools remain the sources of intelligence, while Theseus provides the workflow that connects them.

---

# Roadmap

Theseus is being developed incrementally, with a focus on expanding the collector ecosystem and improving the investigation responders for each supported entity type.

Planned development areas include:

- Additional OSINT collectors
- Expanded entity support
- More cross-source correlation
- Improved investigation reports
- Better collector error handling
- Concurrent collection
- Collector configuration
- Expanded local-tool integration
- Improved CLI experience

The architecture is intended to support additional collectors and investigation capabilities without requiring the entire workflow to be redesigned each time a new tool is integrated.

---

## License

Theseus v1 is licensed under the Apache License 2.0.

See the [LICENSE](LICENSE) file for details.