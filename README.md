## Recon Notes Generator

A simple tool to turn raw reconnaissance output into clean, readable reports.

It takes results from tools like Subfinder, Httpx, and Nmap, and converts them into structured findings with basic risk analysis.

---
##### ⚠️ Use only on systems you have permission to test.
---

## What it does
- Reads recon output from:
  - Subfinder (`.txt`)
  - Httpx (`.json` – JSON lines)
  - Nmap (`.xml`)
- Extracts useful findings (subdomains, URLs, open ports)
  - Assigns a basic risk level:
  - LOW
  - MEDIUM
  - HIGH
- Adds short explanations for why something might be risky
- Exports results in:
  - JSON
  - CSV
  - HTML (simple readable report)

--- 

## Installation

```bash
git clone https://github.com/yagere941-crypto/recon.git
cd recon
```
---

## Make sure Python is installed:
```bash
git clone https://github.com/yagere941-crypto/recon.git
cd recon
```
Note> No extra packages needed — it uses only the standard library.

---

## Usage: 
---
## 1. basic
```bash 
python3 recon.py --input subdomains.txt
```
## 2. Save output to a file
```bash 
python3 recon.py --input httpx.json --output report.json
```
## 3. HTML report
```bash
python3 recon.py --input nmap.xml --format html --output report.html
```
## 4. CSV export
```bash 
python3 recon.py --input httpx.json --format csv --output report.csv
```

---

## Options
- --input → input file (.txt, .json, .xml) (required)
- --output → output file (default: recon_notes.json)
- --format → json, csv, or html
- --verbose → more detailed logs
- --version → show version

---

## How risk is decided

#### This tool uses simple rules (not advanced scoring):

- Open ports
  - Ports below 1024 are treated as higher risk
- Subdomains
  - Names like admin, dev, test increase risk
- URLs
  - No WAF detected → more risky
  - 5xx status codes → possible server issues

#### This is meant for quick insight, not a full security assessment.

---
## Example output (JSON)
```JSON
{
  "summary": {
    "HIGH": 2,
    "MEDIUM": 3,
    "LOW": 5
  },
  "total_findings": 10,
  "findings": [
    {
      "type": "port",
      "value": "192.168.1.1:22",
      "risk": "HIGH",
      "risk_score": 5,
      "explanations": [
        "Privileged port 22 is accessible"
      ],
      "mitigations": [
        "Review security configuration"
      ]
    }
  ]
}
```
---
## Notes
- The tool skips broken or malformed data instead of crashing
- Handles Ctrl+C safely
- Logging is written to both console and a log file
---
## Limitations
- Uses simple rule-based logic (no real AI yet)
- Risk scoring is basic
- Mitigation advice is generic
- CSV output is minimal
---
## Future ideas
- Better scoring (CVSS or similar)
- Support for more tools
- Markdown reports
- Smarter analysis
---
## Disclaimer

#### This project is for learning and authorized testing only.
#### Do not use it on systems without permission.
---
