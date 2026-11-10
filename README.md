⚡ NIKOLA SCANER v5.1

Advanced Web Security Auditor & Attack Surface Intelligence

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.10%2B-blue?logo=python&logoColor=white" alt="Python"/>
  <img src="https://img.shields.io/badge/Version-5.1-purple" alt="Version"/>
  <img src="https://img.shields.io/badge/Platform-Termux%20%7C%20Linux%20%7C%20Windows%20%7C%20macOS-green" alt="Platform"/>
  <img src="https://img.shields.io/badge/Category-Cybersecurity-red" alt="Category"/>
  <img src="https://img.shields.io/badge/Author-NIKOLA%20TESLA-orange" alt="Author"/>
  <img src="https://img.shields.io/badge/Country-Tanzania 🇹🇿-blue" alt="Country"/>
</p><p align="center">
  <b>RECONNAISSANCE • SECURITY ANALYSIS • VULNERABILITY DETECTION • INTELLIGENCE</b>
</p>---

🌐 Overview

NIKOLA SCANER v5.1 is a Python-based web security auditing and attack surface assessment tool designed for ethical hackers, penetration testers, bug bounty hunters, and system administrators.

Built with a multi-layer security analysis architecture, NIKOLA SCANER examines web applications, identifies security misconfigurations, evaluates defensive mechanisms, and generates comprehensive HTML security reports.

The tool combines:

- 🔍 Deep web reconnaissance.
- 🛡️ Multi-layer security analysis.
- 🔐 TLS/SSL configuration auditing.
- 🌐 DNS security assessment.
- 📡 HTTP security header inspection.
- 🧩 Technology and dependency identification.
- 📂 Sensitive resource exposure checks.
- 📊 Automated HTML reporting.
- 🗂️ Persistent scan history.

Its objective is simple:

Understand the security posture of a web application, identify potential weaknesses, and present actionable findings in a professional report.

---

👨‍💻 About the Author

Information| Details
Project| NIKOLA SCANER
Version| v5.1
Author| NIKOLA TESLA
Country| Tanzania 🇹🇿
Email| hacklab01001@gmail.com
Programming Language| Python 3
Project Category| Web Security Auditing

Developer: NIKOLA TESLA
Made with dedication in Tanzania 🇹🇿

---

🚀 Features

NIKOLA SCANER v5.1 combines several security auditing capabilities into one interactive tool.

1. 🛡️ Multi-Layer Security Probing

Evaluates the HTTP responses and defensive mechanisms encountered during authorized security assessments.

Detection capabilities:

- Cloudflare protection identification.
- Akamai protection identification.
- Sucuri protection identification.
- Access Control List (ACL) indicators.
- HTTP 429 Rate Limiting detection.
- HTTP 401 Authentication detection.
- HTTP redirect analysis.
- HTTP response behavior classification.

Security classification:

Classification| Description
🔴 HARD| Strong defensive indicators detected.
🟡 STANDARD| Standard security mechanisms identified.
🟠 EASY| Limited defensive indicators observed.
🟢 OPEN| No significant defensive indicators observed.

These classifications represent observed responses, not a definitive measurement of overall security.

2. 🧠 Controlled Header Variation & Deception Testing

The tool can perform controlled HTTP request variations to evaluate how applications and security controls respond to different request metadata.

Testing capabilities include:

- User-Agent variation.
- Referer variation.
- X-Requested-With header testing.
- Forwarded-IP header handling.
- Proxy-related header handling.
- Response comparison across request variations.
- Configurable retry limits.

Example HTTP metadata examined:

User-Agent: Security-Audit-Client
X-Forwarded-For: 127.0.0.1
CF-Connecting-IP: 127.0.0.1
X-Requested-With: XMLHttpRequest
Referer: https://example.com/

Security objective:

Identify applications that incorrectly trust client-controlled headers or expose inconsistent access-control behavior.

«⚠️ Header manipulation is a testing technique, not a reliable method of bypassing WAFs, authentication, or access controls. Findings should be verified against the application's actual security configuration.»

3. 🔍 Deep Security Auditing Modules

NIKOLA SCANER includes multiple auditing categories.

A. HTTP Security Headers

Examines important HTTP response headers:

Header| Security Purpose
Strict-Transport-Security| Enforces HTTPS connections.
Content-Security-Policy| Restricts permitted content sources.
X-Frame-Options| Helps prevent clickjacking.
X-Content-Type-Options| Prevents MIME-type sniffing.
Referrer-Policy| Controls referrer information.
Permissions-Policy| Controls browser feature permissions.

B. TLS/SSL Analysis

Evaluates the target's HTTPS configuration.

Potential inspection areas:

- TLS protocol version.
- Supported cipher information.
- SSL/TLS certificate issuer.
- Certificate expiration date.
- Certificate validity.
- HTTPS configuration indicators.

C. DNS Security Analysis

Examines DNS configuration and email authentication records.

DNS Record| Purpose
A| IPv4 address resolution.
AAAA| IPv6 address resolution.
MX| Mail server identification.
NS| Authoritative nameservers.
SPF| Email sender authorization.
DMARC| Email authentication policy.
DNSSEC| DNS response authenticity.
CAA| Certificate authority authorization.

D. Sensitive Path Exposure Detection

Checks authorized targets for potentially exposed resources and configuration files.

Examples:

/.git/
/.env
/backup/
/backup.zip
/phpinfo.php

The objective is to identify accidental information exposure and report the associated evidence.

E. Dependency Security Analysis

Identifies commonly used web technologies and dependencies.

Examples include:

- jQuery
- Bootstrap
- Angular
- Other detectable JavaScript libraries and frameworks.

Where reliable version information is available, the tool can compare detected dependencies against known vulnerability information, including CVE references.

F. Content Security & Information Disclosure

Examines potential information disclosure indicators, including:

- Mixed-content references.
- Exposed server error messages.
- Debug information.
- Publicly exposed configuration indicators.
- Potential API key exposure.
- Unnecessary technology disclosure.

Detection results require manual verification. A detected pattern does not automatically prove that a credential or vulnerability is exploitable.

---

⚙️ How It Works

NIKOLA SCANER uses a structured auditing workflow.

Security Assessment Workflow

       ┌──────────────────────┐
       │     START SCAN       │
       └──────────┬───────────┘
                  │
                  ▼
       ┌──────────────────────┐
       │  Target Validation   │
       └──────────┬───────────┘
                  │
                  ▼
       ┌──────────────────────┐
       │  HTTP Reconnaissance │
       └──────────┬───────────┘
                  │
                  ▼
       ┌──────────────────────┐
       │ Multi-Layer Analysis │
       └──────────┬───────────┘
                  │
                  ▼
       ┌──────────────────────┐
       │  Security Modules    │
       │                      │
       │ • HTTP Headers       │
       │ • TLS/SSL            │
       │ • DNS Security       │
       │ • Sensitive Paths    │
       │ • Dependencies       │
       │ • Information Leak   │
       └──────────┬───────────┘
                  │
                  ▼
       ┌──────────────────────┐
       │ Evidence Collection  │
       └──────────┬───────────┘
                  │
                  ▼
       ┌──────────────────────┐
       │  HTML Report Engine  │
       └──────────┬───────────┘
                  │
                  ▼
       ┌──────────────────────┐
       │   Scan History       │
       └──────────┬───────────┘
                  │
                  ▼
       ┌──────────────────────┐
       │    END SCAN          │
       └──────────────────────┘

Multi-Layer Probing Architecture

The probing engine evaluates how a target responds to different HTTP requests.

It examines:

1. HTTP status codes.
2. Redirect behavior.
3. Authentication requirements.
4. Rate-limiting responses.
5. WAF identification indicators.
6. Access-control responses.
7. Changes in responses across controlled request variations.

The results help security researchers understand which defensive mechanisms are visible from the testing environment.

Retry & Request Variation

The configured request engine supports up to five retries.

During authorized testing, request variations can help identify inconsistent server behavior.

All testing should respect the target's rate limits and access policies.

---

📱 Installation

NIKOLA SCANER supports multiple operating systems.

1. Termux (Android)

One of the main advantages of NIKOLA SCANER is its compatibility with Android through Termux.

Step 1 — Update packages

pkg update && pkg upgrade -y

Step 2 — Install Python and Git

pkg install python git -y

Step 3 — Install dependencies

pip install requests beautifulsoup4 dnspython urllib3

Step 4 — Navigate to the project directory

cd nikola-scaner

Step 5 — Launch the tool

python nikola_scaner.py

2. Linux

Install Python 3 and pip:

sudo apt update
sudo apt install python3 python3-pip git -y

Install the dependencies:

python3 -m pip install requests beautifulsoup4 dnspython urllib3

Launch:

python3 nikola_scaner.py

3. Windows

Install Python 3 from:

https://www.python.org/downloads/

Open PowerShell or Command Prompt.

Install dependencies:

py -m pip install requests beautifulsoup4 dnspython urllib3

Navigate to the project directory:

cd nikola-scaner

Launch:

py nikola_scaner.py

4. macOS

Install Python 3 and dependencies:

brew install python

python3 -m pip install requests beautifulsoup4 dnspython urllib3

Launch:

python3 nikola_scaner.py

---

🎮 Usage

NIKOLA SCANER supports interactive and direct command-line execution.

Interactive Mode

Start the application:

python nikola_scaner.py

The tool opens its interactive terminal interface.

Example interface:

==================================================
             NIKOLA SCANER v5.1
       ADVANCED WEB SECURITY AUDITOR
==================================================

 [1] Start Security Scan
 [2] Scan History
 [3] View Previous Reports
 [4] About NIKOLA SCANER
 [0] Exit

==================================================

 Select an option:

Menu labels are illustrative and should match the actual implementation.

Direct Scan Mode

You can also specify a target directly:

python nikola_scaner.py https://example.com

The scanner will begin its configured security assessment.

Replace "example.com" with a domain you own or have explicit authorization to test.

---

📊 Smart Local Server Report Viewer

<sup>⭐ One of the key usability features of NIKOLA SCANER v5.1</sup>

NIKOLA SCANER includes an interactive HTML report viewing workflow.

After completing a scan, the application prompts:

Open web [y/n]?

If the user enters:

y

The application starts its local report-viewing server on port:

8080

It then opens the generated HTML report in the device's web browser.

Why Is This Useful?

Android and Termux users sometimes encounter difficulties opening locally generated HTML files directly.

The local server provides another way to access the report through a browser.

Benefits:

- 🌐 Browser-based HTML report viewing.
- 📱 Convenient Android and Termux support.
- ⚡ Automatic report-opening workflow.
- 🎨 Full HTML styling and formatting.
- 📊 Easy navigation through security findings.

Example

[+] Scan completed successfully!

[+] HTML report generated.
[+] Report saved.

Open web [y/n]? y

[+] Starting local report server...
[+] Port: 8080

[+] Opening security report...

Security recommendation: The local server should bind exclusively to "127.0.0.1" unless remote access is explicitly required and properly protected. It should serve only generated reports and must not expose the device's filesystem.

---

🗂️ Scan History Management

NIKOLA SCANER includes persistent scan history.

Previous scan information is stored in a JSON file.

This allows users to revisit earlier assessments without repeating every scan.

History Capabilities

- View previous scans.
- Review saved scan information.
- Access previously generated reports.
- Compare historical security findings.
- Maintain an organized assessment record.

Example storage structure:

nikola-scaner/
│
├── nikola_scaner.py
├── scan_history.json
│
├── reports/
│   ├── report_001.html
│   ├── report_002.html
│   └── report_003.html
│
└── README.md

The directory structure above is an illustrative example.

---

🎨 Terminal Interface & HTML Reporting

NIKOLA SCANER focuses on presenting technical findings in an understandable format.

Terminal Interface

Features include:

- Modern colored terminal output.
- Organized scan progress.
- Clear security classifications.
- Readable detection messages.
- Interactive navigation.

HTML Security Reports

Generated reports are designed around a dark cybersecurity theme.

Report components include:

Component| Description
Executive Summary| Overview of the assessment.
Security Findings| Identified security issues.
Severity Indicators| Visual severity classifications.
Evidence Tables| Supporting technical observations.
HTTP Analysis| Response and header information.
DNS Analysis| DNS security observations.
TLS Analysis| Certificate and protocol information.
Recommendations| Suggested remediation actions.

The objective is to transform technical scan results into readable security documentation.

---

📦 Dependencies

NIKOLA SCANER is developed using Python 3.

Its primary dependencies are:

Library| Purpose
"requests"| HTTP communication.
"beautifulsoup4"| HTML parsing and analysis.
"dnspython"| DNS record inspection.
"urllib3"| HTTP transport utilities.

Install all dependencies:

pip install requests beautifulsoup4 dnspython urllib3

---

💻 Platform Compatibility

Platform| Support
Android (Termux)| ✅
Linux| ✅
Windows| ✅
macOS| ✅

Recommended environment: Python 3.10 or newer.

---

🔐 Security & Responsible Use

NIKOLA SCANER is intended for legitimate cybersecurity research and authorized security auditing.

Users should:

- Obtain permission before scanning a system.
- Follow the scope of authorized penetration tests.
- Respect rate limits and service restrictions.
- Avoid disrupting production services.
- Protect scan reports and collected evidence.
- Avoid accessing or retaining private information unnecessarily.
- Report discovered vulnerabilities responsibly.

---

⚖️ Legal Disclaimer

IMPORTANT — READ BEFORE USING NIKOLA SCANER

NIKOLA SCANER is provided as a cybersecurity auditing and educational tool.

It is designed for:

- Authorized penetration testing.
- Security research.
- Bug bounty programs operating within their published scope.
- Testing personally owned web applications.
- Defensive security assessments.
- Educational cybersecurity laboratories.

Unauthorized testing is not permitted.

Scanning, probing, manipulating HTTP requests, or attempting to access systems without proper authorization may violate applicable laws and regulations.

The author and contributors are not responsible for misuse of this software, unauthorized access, service disruption, data loss, or damages resulting from improper use.

By using NIKOLA SCANER, you accept responsibility for ensuring that your activities comply with applicable laws and authorization requirements.

---

🛠️ Project Information

Property| Value
Tool Name| NIKOLA SCANER
Current Version| v5.1
Author| NIKOLA TESLA
Development Country| Tanzania 🇹🇿
Language| Python 3
Project Type| Web Security Auditor
Report Format| HTML
Scan History| JSON
Local Report Port| 8080

---

📬 Contact & Support

For project-related questions, technical discussions, or collaboration:

Author: NIKOLA TESLA

Country: Tanzania 🇹🇿

Email: hacklab01001@gmail.com

---

<p align="center">
  <b>⚡ NIKOLA SCANER v5.1</b>
  <br/>
  <i>See the surface. Understand the exposure. Strengthen the defense.</i>
  <br/><br/>
  <b>DEVELOPED IN TANZANIA 🇹🇿</b>
</p>---

NIKOLA SCANER — ADVANCED WEB SECURITY INTELLIGENCE.
