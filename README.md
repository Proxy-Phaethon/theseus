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

Theseus is an OSINT investigation tool that brings existing intelligence tools and services together behind a single workflow.

Give Theseus a target such as an IP address, domain, email address, username, or URL. Theseus identifies the target, selects the relevant collectors, gathers information from those sources, and organizes their findings into an investigation report.

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

It does not attempt to replace the individual tools it uses. Instead, it connects them, routes targets to relevant collectors, and organizes their findings into a structured report.

---

## Current Status

**Version: v0.6.0**

Theseus uses an entity-based architecture. The identifier determines the target type, the collector registry selects the relevant tools, and the responder organizes their results into an investigation report.

The current implementation supports five entity types:

- IP addresses
- Domains
- Email addresses
- Usernames
- URLs

Each supported entity has its own collector ecosystem and responder. Theseus combines observations from multiple sources while retaining distinctions between different types of findings.

At v0.6.0, the investigation workflows for all five supported entity types are implemented. Development is shifting toward improving the consistency, reliability, usability, and overall presentation of the existing system ahead of v1.0.0.

The architecture remains extensible, allowing additional collectors and capabilities to be integrated without redesigning the entire workflow.

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

On macOS using Zsh, you can add this to your shell configuration:

```bash
echo 'export SHODAN_API_KEY="your-api-key"' >> ~/.zshrc
source ~/.zshrc
```

Other collectors may require their own credentials, configuration, or locally installed command-line tools.

API keys should never be committed to the repository. Consult the documentation for each integrated tool to determine its configuration requirements.

## Usage

Start Theseus:

```bash
theseus
```

Enter a target at the prompt:

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

During collection, Theseus displays a terminal loading indicator while the tools run. When collection finishes, the relevant responder organizes the collected observations into an investigation report.

Enter `q` to exit.

---

# Investigations

## IP Addresses

IP investigation combines network intelligence, infrastructure observations, reputation data, and internet exposure information from multiple independent sources.

The IP collector ecosystem covers:

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

For example, if different sources report different locations, Theseus can preserve the disagreement:

```text
Observations

  Region mismatch:
    California (1 source)
    Virginia (1 source)

  City mismatch:
    Mountain View (1 source)
    Ashburn (1 source)
```

The goal is to preserve collected evidence rather than manufacture certainty where the sources disagree.

## Domains

Domain investigation examines registration details, DNS infrastructure, related assets, and potential exposure.

The domain collector ecosystem covers:

- **WHOIS and RDAP:** Registration details, registrar information, dates, and domain status.
- **DNS:** Records, nameservers, and related infrastructure.
- **Subdomains:** Discovery of additional assets associated with a domain.
- **Email posture:** DNS-based email infrastructure and security configuration, including SPF and DMARC checks.
- **Certificates and threat intelligence:** Domain-related certificate and reputation observations.
- **Hosting and IPs:** Infrastructure associated with the target domain.

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

The email responder organizes findings into five areas.

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

URL investigation examines a specific URL through HTTP requests, DNS lookups, browser inspection, threat-intelligence sources, certificate records, and web archives.

Unlike a basic URL checker, Theseus combines observations from multiple collectors into one report, making it easier to examine a URL's behavior, infrastructure, reputation, and historical presence.

### HTTP and DNS

The HTTP collector examines the URL's response and redirect behavior.

Collected observations can include:

- Requested URL
- Final URL
- HTTP status and reason
- Redirect chain
- Response headers
- Content type
- Response size
- Response time

The DNS collector retrieves records associated with the URL's hostname, including:

- A and AAAA records
- CNAME records
- MX records
- NS records
- TXT records

Together, these findings provide a starting point for understanding how the URL resolves and responds.

### Browser inspection

**Playwright** examines the target using a browser session.

Depending on the page and the information available, the responder can report:

- Final URL and page title
- Browser HTTP status and content type
- Redirect chain
- DOM length and SHA-256 fingerprint
- Links found on the page
- Forms and their fields
- Browser network requests and resource types
- Failed requests
- JavaScript console errors
- Page errors
- Elapsed inspection time

This provides a view of the page as a browser loads it, complementing the HTTP collector's direct request.

### Infrastructure and certificates

**URLScan** provides scan observations that can include:

- Page title and final scanned URL
- Observed IP addresses
- ASN and network organization
- Server information
- TLS certificate metadata
- Domain age and ranking information
- Observed domains, URLs, and linked domains
- Scan verdicts and request statistics

**Certificate Transparency** uses `crt.sh` to retrieve certificate records associated with the queried domain.

The responder can report certificate counts, concrete hostnames, wildcard patterns, and selected certificate metadata.

Wildcard certificate names are kept distinct from concrete hostnames. A certificate for `*.example.com`, for instance, does not establish that every possible subdomain exists.

### Threat intelligence

Theseus integrates several sources for URL-related reputation and threat observations.

- **VirusTotal:** Retrieves an existing URL report, including available analysis statistics, reputation, categories, community votes, and outgoing links.
- **Google Safe Browsing:** Checks whether the URL matches supported threat lists.
- **URLhaus:** Checks for matching URL records associated with malware distribution.

These sources are reported separately because they have different coverage, data, and detection methods.

A missing record or a lack of detections is not proof that a URL is safe. Community votes, automated engine results, and reputation scores may also disagree and should be interpreted in context.

### Web archives

Theseus uses two archive sources to investigate historical web presence.

**Wayback Machine** retrieves archived captures, including timestamps, original URLs, status codes, and links to individual archived pages.

**Common Crawl** searches its available crawl index for captures associated with the queried domain. The report can include the index used, capture timestamps, URLs, status codes, and content digests.

Archive results can help establish that a URL or domain appeared in a particular crawl or snapshot. They do not necessarily establish ownership, malicious intent, or the complete history of a website.

### URL collectors

Current URL collectors include:

- **HTTP**
- **DNS**
- **Certificate Transparency (`crt.sh`)**
- **VirusTotal**
- **Common Crawl**
- **Playwright**
- **Google Safe Browsing**
- **URLhaus**
- **URLScan**
- **Wayback Machine**

Individual collectors may fail because of timeouts, rate limits, unavailable services, or other external dependencies. Theseus can still produce a report from the collectors that return results.

---

## License

Theseus is licensed under the Apache License 2.0.

See the [LICENSE](LICENSE) file for details.

<div align="center"> <pre>
░▒▓████████▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓████████▓▒░░▒▓███████▓▒░▒▓████████▓▒░▒▓█▓▒░░▒▓█▓▒░░▒▓███████▓▒░ 
   ░▒▓█▓▒░   ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░      ░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░        
   ░▒▓█▓▒░   ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░      ░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░        
   ░▒▓█▓▒░   ░▒▓████████▓▒░▒▓██████▓▒░  ░▒▓██████▓▒░░▒▓██████▓▒░ ░▒▓█▓▒░░▒▓█▓▒░░▒▓██████▓▒░  
   ░▒▓█▓▒░   ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░             ░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░      ░▒▓█▓▒░ 
   ░▒▓█▓▒░   ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░             ░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░      ░▒▓█▓▒░ 
   ░▒▓█▓▒░   ░▒▓█▓▒░░▒▓█▓▒░▒▓████████▓▒░▒▓███████▓▒░░▒▓████████▓▒░░▒▓██████▓▒░░▒▓███████▓▒░  
</pre>