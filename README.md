# HeavenlyEyes

**All-seeing OSINT Reconnaissance CLI Tool**

HeavenlyEyes is a comprehensive open-source intelligence (OSINT) command-line tool built in Python. It automates reconnaissance across domains, emails, social networks, businesses, and leaked data — all from your terminal.

---

## Features

### Domain Intelligence
- **WHOIS Lookup** — Registrar, dates, registrant info, name servers
- **DNS Records** — A, AAAA, MX, NS, TXT, CNAME, SOA, SRV, CAA, PTR
- **SSL/TLS Certificates** — Subject, issuer, SANs, validity dates
- **Subdomain Enumeration** — Multi-threaded DNS brute force (120+ wordlist)
- **Technology Detection** — Frameworks, CMS, CDNs, analytics, security headers
- **Cloud Storage Discovery** — AWS S3, Azure Blob, GCS, DigitalOcean, Firebase
- **Third-Party Services** — Detect 50+ third-party integrations
- **Origin IP Discovery** — Find real IPs hidden behind CDN/WAF (Cloudflare, Akamai, AWS CloudFront, Fastly, Sucuri, Imperva, etc.)
- **CDN/WAF Detection** — Identify which CDN or WAF is protecting a domain

### Email Reconnaissance
- **Email Validation** — Format + MX record verification
- **Pattern Generation** — Generate common email formats for a person
- **Breach Checking** — HaveIBeenPwned + free alternatives
- **Email Harvesting** — Scrape emails from public pages

### Social Network Profiling
- **Username Search** — Check 30+ platforms simultaneously
- **Compounded Search** — Find related username variations

### Business Investigation
- **Organization Info** — Title, description, structured data, Open Graph
- **Location Discovery** — Addresses from structured data and regex patterns
- **Staff Discovery** — Team members from public pages and JSON-LD
- **Contact Information** — Emails, phones, social links
- **Business Records** — Copyright, VAT, registration numbers, legal pages
- **Services/Products** — Discover offerings from public pages

### Leaked Information
- **Breach Database** — Check domain involvement in known breaches
- **Web Archives** — Wayback Machine snapshot history
- **Exposed Files** — Check 35+ sensitive paths (.env, .git, configs, etc.)
- **Paste/Code Leaks** — Search GitHub for code mentions

### Intelligence Analysis
- **Risk Scoring** — Automated 0-100 risk assessment
- **Attack Surface Mapping** — Identify exposed vectors
- **Recommendations** — Actionable security improvement suggestions
- **JSON & HTML Reports** — Export findings for documentation

---

## Installation

```bash
# Clone the repository
git clone https://github.com/worldtreeboy/heavenly-eyes.git
cd heavenly-eyes

# Install (recommended: use a virtual environment)
python -m venv .venv
source .venv/bin/activate  # Linux/macOS
# .venv\Scripts\activate   # Windows

pip install -e .
```

---

## Usage

### Full Scan
```bash
# Complete OSINT scan on a domain
heavenlyeyes scan example.com

# With HTML report output
heavenlyeyes scan example.com --html

# Skip slow modules
heavenlyeyes scan example.com --skip-subdomains --skip-cloud

# Custom output directory
heavenlyeyes scan example.com -o ./my-reports
```

### Domain Commands
```bash
heavenlyeyes domain whois example.com
heavenlyeyes domain dns example.com
heavenlyeyes domain subdomains example.com -t 30
heavenlyeyes domain ssl example.com
heavenlyeyes domain tech example.com
heavenlyeyes domain cloud example.com
heavenlyeyes domain third-parties example.com
heavenlyeyes domain origin example.com         # Find real IP behind CDN/WAF
heavenlyeyes domain cdn-detect example.com     # Detect CDN/WAF provider
```

#### Origin IP Discovery Techniques
| Method | Description | Confidence |
|---|---|---|
| MX Records | Mail servers often bypass CDN | HIGH |
| SPF Records | `ip4:` directives leak the real server | HIGH |
| Subdomain Bypass | 50+ subs like `mail.`, `ftp.`, `cpanel.` skip CDN | HIGH |
| DNS History | Pre-CDN IPs via ViewDNS | MEDIUM |
| CT Log Subdomains | crt.sh certificate transparency lookups | MEDIUM |
| Header Leaks | `X-Real-IP`, `X-Originating-IP`, etc. | HIGH |
| Favicon Hash | Hash favicon and search Shodan for matches | HIGH |

### Email Commands
```bash
heavenlyeyes email validate user@example.com
heavenlyeyes email patterns John Doe example.com
heavenlyeyes email breach user@example.com
heavenlyeyes email harvest example.com
```

### Social Network Commands
```bash
heavenlyeyes social username johndoe
heavenlyeyes social compounded johndoe
```

### Business Investigation
```bash
heavenlyeyes business org example.com
heavenlyeyes business locations example.com
heavenlyeyes business staff example.com
heavenlyeyes business contacts example.com
heavenlyeyes business records example.com
heavenlyeyes business services example.com
heavenlyeyes business full example.com -o ./reports
```

### Leak Investigation
```bash
heavenlyeyes leaks breaches example.com
heavenlyeyes leaks archives example.com
heavenlyeyes leaks exposed example.com
heavenlyeyes leaks pastes example.com
heavenlyeyes leaks full example.com -o ./reports
```

### Short Alias
```bash
# 'heyes' is a shortcut for 'heavenlyeyes'
heyes scan example.com
heyes domain dns example.com
```

---

## Configuration

```bash
# Initialize config
heavenlyeyes config
```

Config file location: `~/.heavenlyeyes/config.yaml`

```yaml
api_keys:
  shodan: ""           # https://shodan.io
  haveibeenpwned: ""   # https://haveibeenpwned.com/API/Key
  hunter_io: ""        # https://hunter.io
  virustotal: ""       # https://virustotal.com

settings:
  timeout: 10
  max_threads: 20
  output_format: json
```

You can also use environment variables:
```bash
export HEYES_SHODAN="your-key"
export HEYES_HAVEIBEENPWNED="your-key"
export HEYES_HUNTER_IO="your-key"
export HEYES_VIRUSTOTAL="your-key"
```

---

## Project Structure

```
heavenly-eyes/
├── heavenlyeyes/
│   ├── cli.py                  # Main CLI entrypoint
│   ├── core/
│   │   ├── config.py           # Configuration management
│   │   ├── utils.py            # Shared utilities & display
│   │   └── reporter.py         # JSON/HTML report generation
│   └── modules/
│       ├── domain/
│       │   ├── records.py      # WHOIS, DNS, SSL
│       │   ├── structure.py    # Subdomain enumeration
│       │   ├── cloud_storage.py
│       │   ├── technologies.py
│       │   ├── third_parties.py
│       │   └── origin_ip.py    # CDN/WAF bypass, origin IP discovery
│       ├── email/
│       │   └── recon.py        # Validation, patterns, breaches
│       ├── social/
│       │   └── networks.py     # Username search (30+ platforms)
│       ├── business/
│       │   └── organization.py # Org, staff, contacts, records
│       ├── leaks/
│       │   └── breaches.py     # Breaches, archives, exposed files
│       └── intelligence/
│           └── analyzer.py     # Risk scoring & recommendations
├── tests/
├── pyproject.toml
├── requirements.txt
└── README.md
```

---

## Disclaimer

This tool is intended for **authorized security testing**, **OSINT research**, **CTF competitions**, and **educational purposes** only. Always ensure you have proper authorization before conducting reconnaissance on any target. The developers are not responsible for any misuse of this tool.

---

## License

MIT License — see [LICENSE](LICENSE) for details.
