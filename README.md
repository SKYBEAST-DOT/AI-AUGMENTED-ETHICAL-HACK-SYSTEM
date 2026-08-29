# Ethical Hacking & Vulnerability Assessment System

> **AUTHORIZED SECURITY TESTING ONLY**
>
> This toolkit is designed only for localhost, intentionally vulnerable labs, and explicitly authorized targets.

## Project Overview

This portfolio project demonstrates a practical, safe ethical-hacking workflow:

**Reconnaissance → Enumeration → Vulnerability Assessment → Analysis → Risk Rating → Report**

The system performs non-destructive checks and produces professional assessment output suitable for lab and training environments.

## Features

- Target management with authorization confirmation
- Safety-oriented scope control (localhost/private networks by default)
- Reconnaissance (DNS, availability, headers, robots.txt, TLS certificate metadata)
- Port & service enumeration (Nmap when available; safe socket fallback)
- Web security checks (headers, HTTPS support, cookie flags, basic exposure checks)
- OWASP-aligned finding categories
- Transparent severity scoring (Informational/Low/Medium/High/Critical)
- Streamlit dashboard with scan history and findings overview
- HTML report generation with methodology, impact, and remediation guidance
- SQLite persistence for targets, scans, findings, and reports

## Architecture

```text
ethical-hacking-system/
├── app.py
├── requirements.txt
├── config/
│   └── safety.py
├── modules/
│   ├── reconnaissance.py
│   ├── port_scanner.py
│   ├── web_checks.py
│   ├── vulnerability_assessment.py
│   ├── risk_scoring.py
│   └── reporting.py
├── database/
│   └── db.py
├── reports/
├── tests/
└── screenshots/
```

## Technologies

- Python 3.10+
- Streamlit
- Requests
- BeautifulSoup (available for HTML parsing extensions)
- Pandas
- SQLite
- JSON
- Nmap (optional, if installed)

## Installation

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Usage

Run the dashboard:

```bash
streamlit run app.py
```

Then open the live web page in your browser:

```text
http://localhost:8501
```

From the UI:
1. Add a target.
2. Confirm authorization explicitly before scanning.
3. Run a safe scan.
4. Review findings and severity distribution.
5. Generate an HTML report.

## Example Safe Lab Workflow

1. Start a local lab target (`localhost` or private lab VM).
2. Add the target in the dashboard with authorization note.
3. Run low-intensity scan.
4. Review findings and manually validate each item.
5. Export the report and remediate detected weaknesses.

## Security & Authorization Disclaimer

- Never scan systems without explicit legal authorization.
- Automated checks produce indicators, not guaranteed vulnerabilities.
- Manual verification is required before acting on findings.
- This project intentionally excludes offensive features such as malware, credential theft, persistence, DDoS, phishing, and destructive exploitation.

## Limitations

- Automated checks are intentionally conservative.
- Nmap-based depth depends on local tool availability.
- Findings can include false positives and always require manual confirmation.
- Report format is currently HTML only.

## Future Improvements

- PDF export support
- Additional authenticated lab checks
- Expanded OWASP mapping logic
- CVE enrichment for identified service versions
- Better long-term trend analytics in dashboard

## Screenshots

Add screenshots of:
- target management
- scan execution
- findings dashboard
- generated report
