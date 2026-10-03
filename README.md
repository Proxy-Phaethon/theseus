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

## Current Status

Theseus is currently at **v0.1.0**.

This is an early project and the collector set is still growing. The goal for v1 is to have a simple foundation that can collect useful information from different sources and present it in one place.

## Installation

You can install Theseus directly from GitHub:

```bash
pip install git+https://github.com/Proxy-Phaethon/theseus.git
```

After installation, the `theseus` command should be available in your terminal:

```bash
theseus
```

## API Keys

Some collectors require API keys.

For example, Shodan requires:

```bash
export SHODAN_API_KEY="your-api-key"
```

On macOS, you can add this to your `~/.zshrc` so it only needs to be configured once:

```bash
echo 'export SHODAN_API_KEY="your-api-key"' >> ~/.zshrc
source ~/.zshrc
```

Other collectors may be added with their own API keys as the project grows.

Never commit API keys or `.env` files to the repository.

## Usage

Start Theseus:

```bash
theseus
```

Then provide a target:

```text
> 8.8.8.8
```

```text
> wikipedia.com
```

```text
> someone@example.com
```

```text
> @username
```

```text
> https://example.com
```

Enter `q` to exit.

Theseus determines the entity type automatically and selects the collectors associated with it.

## What Theseus Can Investigate

### IP addresses

Current collector:

* **Shodan**

Theseus can collect information such as:

* Organization
* ISP
* Hostnames
* Domains
* Open ports
* Services
* Location
* TLS information
* Web information
* Network information

### Domains

Current collectors:

* **LDNS**
* **RDAP**

These provide information including:

* Domain identity
* Web presence
* Redirects
* HTTP security headers
* Registrar
* Registration dates
* Expiration dates
* Domain status
* Nameservers
* DNSSEC

### Email addresses

Current collectors:

* **XposedOrNot**
* **Disify**

These provide information such as:

* Email/domain information
* Domain characteristics
* Disposable email detection
* Role account detection
* Free provider detection
* DNS/MX information
* Known breach exposure

### Usernames

Current collector:

* **WhatsMyName**

Theseus uses the WhatsMyName dataset to check usernames across supported websites.

Results can include:

* Site
* Category
* Detected URL
* HTTP status

### URLs

Current collectors:

* **HTTP**
* **DNS**

These collect information about the specific URL being investigated, including:

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

## Collectors

| Target   | Collector   | API Key |
| -------- | ----------- | ------- |
| IP       | Shodan      | Yes     |
| Domain   | LDNS        | No      |
| Domain   | RDAP        | No      |
| Email    | XposedOrNot | No      |
| Email    | Disify      | No      |
| Username | WhatsMyName | No      |
| URL      | HTTP        | No      |
| URL      | DNS         | No      |

## Why Theseus?

There are a lot of OSINT tools scattered across the internet.

Some are APIs. Some are datasets. Some are command-line tools. Some are specialized for one kind of target.

Theseus is an attempt to put some of them behind one simple interface.

Instead of remembering which tool handles which kind of target:

```text
IP       → Shodan
Domain   → LDNS + RDAP
Email    → XposedOrNot + Disify
Username → WhatsMyName
URL      → HTTP + DNS
```

you give Theseus the target and let it figure out where to look.

## Development

Clone the repository:

```bash
git clone https://github.com/Proxy-Phaethon/theseus.git
cd theseus
```

Create a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Install the dependencies:

```bash
pip install -e .
```

Run the development version:

```bash
python main.py
```

## License

MIT License