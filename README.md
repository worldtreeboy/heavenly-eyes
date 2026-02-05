<div align="center">

```
    ██╗  ██╗███████╗ █████╗ ██╗   ██╗███████╗███╗   ██╗██╗  ██╗   ██╗
    ██║  ██║██╔════╝██╔══██╗██║   ██║██╔════╝████╗  ██║██║  ╚██╗ ██╔╝
    ███████║█████╗  ███████║██║   ██║█████╗  ██╔██╗ ██║██║   ╚████╔╝
    ██╔══██║██╔══╝  ██╔══██║╚██╗ ██╔╝██╔══╝  ██║╚██╗██║██║    ╚██╔╝
    ██║  ██║███████╗██║  ██║ ╚████╔╝ ███████╗██║ ╚████║███████╗██║
    ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝  ╚═══╝  ╚══════╝╚═╝  ╚═══╝╚══════╝╚═╝
    ███████╗██╗   ██╗███████╗███████╗
    ██╔════╝╚██╗ ██╔╝██╔════╝██╔════╝
    █████╗   ╚████╔╝ █████╗  ███████╗
    ██╔══╝    ╚██╔╝  ██╔══╝  ╚════██║
    ███████╗   ██║   ███████╗███████║
    ╚══════╝   ╚═╝   ╚══════╝╚══════╝
```

### 👁️ *All-seeing OSINT Reconnaissance — v2.0*

[![Python](https://img.shields.io/badge/Python-3.9+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Windows-blue?style=for-the-badge)]()
[![GitHub stars](https://img.shields.io/github/stars/worldtreeboy/heavenly-eyes?style=for-the-badge&color=yellow)](https://github.com/worldtreeboy/heavenly-eyes/stargazers)
[![GitHub issues](https://img.shields.io/github/issues/worldtreeboy/heavenly-eyes?style=for-the-badge)](https://github.com/worldtreeboy/heavenly-eyes/issues)

**A powerful, modular OSINT command-line tool that automates reconnaissance across domains, emails, social networks, businesses, and leaked data.**

*Uncover the invisible. Track every digital footprint.*

[📦 Installation](#-installation) •
[🚀 Quick Start](#-quick-start) •
[📖 Documentation](#-modules) •
[⚙️ Configuration](#%EF%B8%8F-configuration) •
[🤝 Contributing](#-contributing)

---

</div>

## ✨ Why HeavenlyEyes?

> Most OSINT tools do one thing. **HeavenlyEyes does everything** — from a single input.

- 🧬 **Recursive Pivot Engine** — give it a username, email, domain, or IP and it automatically branches out to map the entire digital footprint
- 🥷 **Smart Stealth Layer** — rotating browser fingerprints, randomized delays, bot detection bypass
- 🔎 **Google Dorking Engine** — 50+ automated dork queries for exposed data, configs, and admin panels
- 🧠 **AI Synthesis** — LLM-powered analysis generates a "Digital Footprint Summary" with risk assessment
- 📊 **Confidence Scoring** — every finding rated 0-100% with color-coded confidence bars
- 🌐 **Domain intelligence** — WHOIS, DNS, SSL, subdomains, tech stack, cloud buckets
- 🕵️ **CDN/WAF bypass** — Find real IPs behind Cloudflare, Akamai, AWS via 6 Shodan queries + 7 other techniques
- 📧 **Email recon** — Validation, breach checks, pattern generation, harvesting
- 👤 **Social profiling** — Username search across 30+ platforms in seconds
- 🏢 **Business investigation** — Org info, staff, contacts, locations, records
- 💀 **Leak detection** — Breaches, exposed files, archives, paste site monitoring

---

## 📦 Installation

```bash
git clone https://github.com/worldtreeboy/heavenly-eyes.git
cd heavenly-eyes

# Recommended: use a virtual environment
python -m venv .venv
source .venv/bin/activate  # Linux/macOS
# .venv\Scripts\activate   # Windows

pip install -e .
```

Verify installation:
```bash
heavenlyeyes version
```

---

## 🚀 Quick Start

### Recursive Pivot (v2 Engine)

Give it **any single input** — it figures out the rest:

```bash
# Username → finds profiles, emails, domains, and pivots deeper
heavenlyeyes pivot johndoe

# Email → validates, checks breaches, extracts username & domain, pivots
heavenlyeyes pivot user@example.com --depth 3

# Domain → DNS, WHOIS, tech, emails, pivots to discovered entities
heavenlyeyes pivot example.com --html

# IP → reverse DNS, geolocation, Shodan, pivots to hostnames
heavenlyeyes pivot 93.184.216.34
```

The engine **automatically branches** at each depth:

```
┌── username: johndoe
├──── social_profile: GitHub → found email john@example.com
│     ├── PIVOT email: john@example.com
│     │   ├── domain: example.com
│     │   ├── breach: Found in 2 breaches
│     │   └── PIVOT domain: example.com
│     │       ├── DNS records, WHOIS, tech stack
│     │       └── emails harvested from pages
│     └── PIVOT domain: johndoe.dev (from GitHub blog)
├──── social_profile: Reddit, Twitter, LinkedIn, Steam...
└──── Google Dorks: exposed docs, configs, admin panels
```

### Classic Domain Scan

```bash
heavenlyeyes scan target.com --html -o ./reports
```

### Google Dorking

```bash
heavenlyeyes dork example.com              # List 50+ dork queries
heavenlyeyes dork example.com --execute    # Execute with stealth
```

### Short Alias

```bash
heyes pivot johndoe
heyes scan target.com
heyes dork target.com
```

---

## 📖 Modules

<details open>
<summary><h3>🧬 Recursive Pivot Engine</h3></summary>

The core of v2. Takes **any input** and recursively discovers connected intelligence.

```bash
heyes pivot <target> [--depth 1-4] [--no-dorking] [--no-ai] [--html]
```

| Input Type | What It Does | Pivots To |
|:---|:---|:---|
| **Username** | Searches 30+ platforms, extracts profile data (name, email, bio, location) | Emails, domains, linked accounts |
| **Email** | MX validation, breach checks, Gravatar lookup | Username (local part), domain, linked profiles |
| **Domain** | DNS, WHOIS, tech detection, email harvesting | Emails found, registrant emails, MX hosts |
| **IP** | Reverse DNS, geolocation, Shodan host lookup | Hostnames, associated domains |

**Features:**
- Confidence scoring (0-100%) on every finding with color-coded bars
- Smart Stealth — rotating fingerprints, randomized delays, bot detection bypass
- Google Dorking — 50+ automated queries for exposed data
- AI Synthesis — LLM-powered "Digital Footprint Summary" (Anthropic/OpenAI)
- Rule-based fallback analysis when no LLM key is set

</details>

<details>
<summary><h3>🥷 Smart Stealth Layer</h3></summary>

Built into all requests. No configuration needed — works automatically.

- **17 browser fingerprints** — Chrome, Firefox, Safari, Edge, Brave, Opera, Vivaldi (desktop + mobile)
- **Randomized headers** — Accept-Language, Sec-CH-UA, header ordering shuffled per request
- **Jittered delays** — configurable min/max with randomized timing
- **Bot detection bypass** — detects 429 rate limits, captcha pages, and 403 blocks
- **Auto retry** — exponential backoff with fingerprint rotation on failure
- **Proxy rotation** — optional proxy pool support
- **Session persistence** — cookies maintained across requests

```bash
# Custom stealth timing
heyes pivot target --stealth-min 1.0 --stealth-max 5.0
```

</details>

<details>
<summary><h3>🔎 Google Dorking Engine</h3></summary>

50+ dork templates across 9 categories:

```bash
heyes dork example.com              # Generate queries (dry run)
heyes dork example.com --execute    # Execute with stealth
heyes dork johndoe -x -m 10        # Username dorks, max 10
```

| Category | What It Finds |
|:---|:---|
| `exposed_docs` | PDFs, DOCX, XLSX, CSV, TXT on the domain |
| `config_files` | .env, .yaml, .conf, .log, .sql, .bak files |
| `directory_listings` | Open "index of /" directories, .git exposure |
| `admin_panels` | /admin, /login, /dashboard, /wp-admin |
| `data_exposure` | Passwords in files, RSA keys, AWS keys, API endpoints |
| `error_pages` | PHP errors, stack traces, SQL errors, debug info |
| `emails` | Email addresses in documents and external pages |
| `username_dorks` | Profile mentions on GitHub, LinkedIn, Pastebin, etc. |
| `infrastructure` | Subdomains, staging environments, phpMyAdmin, Swagger |

</details>

<details>
<summary><h3>🧠 AI Synthesis</h3></summary>

Analyzes all findings and generates a **Digital Footprint Summary**.

- Auto-detects `ANTHROPIC_API_KEY` or `OPENAI_API_KEY`
- Structured report: Identity, Digital Presence, Attack Surface, Correlations, Risk, Recommendations
- Falls back to rule-based analysis when no LLM key is set

```bash
# With AI (set your key first)
export ANTHROPIC_API_KEY="sk-ant-..."
heyes pivot johndoe

# Without AI (rule-based fallback, still useful)
heyes pivot johndoe --no-ai
```

</details>

<details>
<summary><h3>🌐 Domain Intelligence</h3></summary>

Full domain reconnaissance suite with 9 specialized commands.

```bash
heyes domain whois example.com          # WHOIS registration data
heyes domain dns example.com            # All DNS record types
heyes domain ssl example.com            # SSL/TLS certificate details
heyes domain subdomains example.com     # Brute-force 120+ subdomains
heyes domain tech example.com           # Detect tech stack & frameworks
heyes domain cloud example.com          # Find exposed cloud buckets
heyes domain third-parties example.com  # Identify 50+ integrations
heyes domain origin example.com         # 🔥 Find real IP behind CDN
heyes domain cdn-detect example.com     # Identify CDN/WAF provider
```

| Feature | Details |
|:---|:---|
| WHOIS Lookup | Registrar, dates, registrant info, name servers, DNSSEC |
| DNS Records | A, AAAA, MX, NS, TXT, CNAME, SOA, SRV, CAA, PTR |
| SSL/TLS | Subject, issuer, SANs, serial, validity period |
| Subdomains | Multi-threaded brute force with 120+ wordlist |
| Tech Detection | CMS, frameworks, CDNs, analytics, security headers |
| Cloud Storage | AWS S3, Azure Blob, GCS, DigitalOcean Spaces, Firebase |
| Third-Party | 50+ services (analytics, payments, chat, CDNs, ads) |

</details>

<details>
<summary><h3>🕵️ Origin IP Discovery (CDN/WAF Bypass)</h3></summary>

The flagship feature. Find the **real server IP** hidden behind CDN and WAF services.

```bash
heyes domain origin example.com
```

Detects and bypasses: **Cloudflare** · **Akamai** · **AWS CloudFront** · **Fastly** · **Sucuri** · **Imperva** · **StackPath** · **Azure CDN** · **Google Cloud CDN** · **DDoS-Guard**

| Technique | How It Works | Confidence |
|:---|:---|:---:|
| 📮 MX Records | Mail servers often point to origin, not CDN | 🟢 HIGH |
| 📝 SPF Records | `ip4:` directives in SPF leak the real IP | 🟢 HIGH |
| 🔀 Subdomain Bypass | `mail.`, `ftp.`, `cpanel.`, `direct.` skip CDN (50+ checked) | 🟢 HIGH |
| ⏳ DNS History | Pre-CDN IPs from historical records | 🟡 MEDIUM |
| 📜 CT Logs | Certificate transparency reveals hidden subdomains | 🟡 MEDIUM |
| 📡 Header Leaks | `X-Real-IP`, `X-Originating-IP`, `X-Forwarded-For` | 🟢 HIGH |
| 🎯 Favicon Hash | Match favicon fingerprint via Shodan | 🟢 HIGH |

</details>

<details>
<summary><h3>📧 Email Reconnaissance</h3></summary>

```bash
heyes email validate user@example.com         # Format + MX verification
heyes email patterns John Doe example.com     # Generate email patterns
heyes email breach user@example.com           # Check breach databases
heyes email harvest example.com               # Scrape emails from pages
```

- ✅ Format validation + MX record verification
- 🔑 14+ email pattern formats per person
- 💀 HaveIBeenPwned + free alternative breach checks
- 🕸️ Scrapes emails from `/contact`, `/about`, `/team` and more

</details>

<details>
<summary><h3>👤 Social Network Profiling</h3></summary>

```bash
heyes social username johndoe       # Search 30+ platforms
heyes social compounded johndoe     # Find username variations
```

Searches simultaneously across:

> GitHub · Twitter/X · Instagram · Reddit · LinkedIn · TikTok · YouTube · Pinterest · Twitch · GitLab · Bitbucket · Medium · Dev.to · Keybase · HackerOne · Steam · Spotify · SoundCloud · Flickr · Mastodon · Gravatar · About.me · HackerNews · StackOverflow · Docker Hub · npm · PyPI · Telegram · Patreon · Substack

</details>

<details>
<summary><h3>🏢 Business Investigation</h3></summary>

```bash
heyes business org example.com          # Organization info
heyes business locations example.com    # Physical addresses
heyes business staff example.com        # Team members
heyes business contacts example.com     # Emails, phones, socials
heyes business records example.com      # Copyright, VAT, legal
heyes business services example.com     # Products & services
heyes business full example.com         # Run all of the above
```

Extracts data from JSON-LD structured data, Open Graph meta tags, page content analysis, and regex pattern matching.

</details>

<details>
<summary><h3>💀 Leaked Information</h3></summary>

```bash
heyes leaks breaches example.com     # Breach database check
heyes leaks archives example.com     # Wayback Machine history
heyes leaks exposed example.com      # Sensitive file detection
heyes leaks pastes example.com       # Paste site & code leaks
heyes leaks full example.com         # Run all of the above
```

Checks **35+ sensitive paths** including:
> `.env` · `.git/config` · `backup.sql` · `phpinfo.php` · `swagger.json` · `wp-config.php.bak` · `admin/` · `api-docs` · `security.txt` · and more

</details>

<details>
<summary><h3>🧠 Intelligence Analysis</h3></summary>

Automatically runs after a full scan. Produces:

- **Risk Score** — 0-100 automated assessment
- **Risk Level** — LOW / MEDIUM / HIGH / CRITICAL
- **Attack Surface** — Exposed subdomains, public buckets, leaked files
- **Recommendations** — Prioritized, actionable security improvements

</details>

---

## ⚙️ Configuration

```bash
heavenlyeyes config
```

Config: `~/.heavenlyeyes/config.yaml`

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

Or use **environment variables**:
```bash
export HEYES_SHODAN="your-key"
export HEYES_HAVEIBEENPWNED="your-key"
export HEYES_HUNTER_IO="your-key"
export HEYES_VIRUSTOTAL="your-key"

# For AI Synthesis (pick one)
export ANTHROPIC_API_KEY="sk-ant-..."
export OPENAI_API_KEY="sk-..."
```

> 💡 **HeavenlyEyes works without API keys** — keys unlock premium features:
>
> | Key | What It Unlocks |
> |:---|:---|
> | `HEYES_SHODAN` | Deep origin IP discovery, host verification, vuln scanning |
> | `HEYES_HAVEIBEENPWNED` | Comprehensive breach database checks |
> | `ANTHROPIC_API_KEY` | AI-powered Digital Footprint Summary (Claude) |
> | `OPENAI_API_KEY` | AI-powered Digital Footprint Summary (GPT) |

---

## 🗂️ Project Structure

```
heavenly-eyes/
├── heavenlyeyes/
│   ├── cli.py                    # CLI entrypoint (Typer)
│   ├── engine/                   # ★ v2.0 Engine Layer
│   │   ├── pivot.py              # Recursive Pivot Engine
│   │   ├── stealth.py            # Smart Stealth (rotating fingerprints)
│   │   ├── confidence.py         # Confidence scoring system
│   │   ├── dorking.py            # Google Dorking Engine (50+ dorks)
│   │   ├── synthesis.py          # AI Synthesis (LLM integration)
│   │   └── dashboard.py          # Rich terminal dashboard
│   ├── core/
│   │   ├── config.py             # Config & API key management
│   │   ├── utils.py              # Shared utilities & Rich display
│   │   └── reporter.py           # JSON & HTML report generation
│   └── modules/
│       ├── domain/
│       │   ├── records.py        # WHOIS, DNS, SSL
│       │   ├── structure.py      # Subdomain enumeration
│       │   ├── cloud_storage.py  # S3, Azure, GCS bucket discovery
│       │   ├── technologies.py   # Tech stack fingerprinting
│       │   ├── third_parties.py  # Third-party service detection
│       │   └── origin_ip.py      # CDN/WAF bypass & origin IP (Shodan)
│       ├── email/
│       │   └── recon.py          # Email validation, breaches, harvest
│       ├── social/
│       │   └── networks.py       # Username search (30+ platforms)
│       ├── business/
│       │   └── organization.py   # Org, staff, contacts, records
│       ├── leaks/
│       │   └── breaches.py       # Breaches, archives, exposed files
│       └── intelligence/
│           └── analyzer.py       # Risk scoring & recommendations
├── tests/
├── pyproject.toml
└── requirements.txt
```

---

## 🤝 Contributing

Contributions are welcome! Here's how:

1. **Fork** the repo
2. **Create** your feature branch (`git checkout -b feature/awesome-module`)
3. **Commit** your changes (`git commit -m 'Add awesome module'`)
4. **Push** to the branch (`git push origin feature/awesome-module`)
5. **Open** a Pull Request

### Ideas for contributions:
- [ ] Phone number OSINT module
- [ ] IP geolocation mapping
- [ ] Dark web monitoring
- [ ] PDF report generation
- [ ] Async/parallel scanning for speed
- [ ] Plugin system for custom modules

---

## ⚠️ Disclaimer

<div align="center">

This tool is intended for **authorized security testing**, **OSINT research**, **CTF competitions**, and **educational purposes** only.

Always ensure you have **proper authorization** before conducting reconnaissance on any target.

The developers assume **no liability** for misuse of this tool.

</div>

---

<div align="center">

## ⭐ Star History

If HeavenlyEyes helped you, **give it a star** — it helps others discover the tool!

[![Star this repo](https://img.shields.io/github/stars/worldtreeboy/heavenly-eyes?style=social)](https://github.com/worldtreeboy/heavenly-eyes)

---

**Built with 🖤 by [worldtreeboy](https://github.com/worldtreeboy)**

MIT License — see [LICENSE](LICENSE)

</div>
