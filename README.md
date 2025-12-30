# AI‑Assisted Recon Notes Generator

An **AI‑assisted reconnaissance report generator** for ethical hacking and security assessments.  
This tool parses outputs from common recon tools and produces **structured, risk‑analyzed reports**.

> ⚠️ **For educational and authorized security testing only**

---

## ✨ Features

- Parses outputs from:
  - **Subfinder** (`.txt`)
  - **Httpx** (`.json` – JSON lines)
  - **Nmap** (`.xml`)
- Automatically analyzes findings and assigns:
  - Risk level (**LOW / MEDIUM / HIGH**)
  - Risk score
  - Explanation
  - Mitigation advice
- Supports multiple output formats:
  - **JSON**
  - **CSV**
  - **HTML**
- Graceful handling of:
  - Invalid files
  - Permission errors
  - Malformed JSON/XML
  - **Ctrl + C (Keyboard Interrupt)**
- Designed for **ethical hackers, bug bounty hunters, and students**

---

## 📁 Supported Input Formats

| Tool        | File Type | Description |
|------------|----------|-------------|
| Subfinder  | `.txt`   | List of discovered subdomains |
| Httpx      | `.json`  | JSON‑lines output |
| Nmap       | `.xml`   | XML scan results |

---

## 🛠 Installation

Clone the repository:

```bash
git clone https://github.com/yagere941-crypto/recon.git
cd recon
```
---

### Ensure Python 3.8+ is installed:
```bash
python3 --version
```

No external dependencies required (uses Python standard library only). 

## 🚀 Usage
Basic Usage
```bash 
python3 recon.py --input subdomains.txt
```
### Specify Output File
```bash 
python3 main.py --input httpx.json --output report.json
```
## Generate HTML Report
```bash 
python3 main.py --input nmap.xml --format html --output report.html
```
## Generate CSV Report
```bash 
python3 main.py --input httpx.json --format csv --output report.csv
```

---

## CLI Options

| Option      | Description |
|-------------|----------------|
| --input     | Input file (.txt, .json, .xml) (required) |
| --output    | Output file name (default: recon_notes.json) |
| --format    | Output format: json, csv, html |

---

## 📊 Risk Analysis Logic (Overview)

- Open ports

  - Privileged ports (<1024) increase risk
---
- Subdomains
    - Keywords like admin, dev, test increase risk
---
- URLs

    - No WAF detected → higher risk

    - 5xx status codes increase risk
---
- Risk Levels:

    - LOW – Minimal exposure

    - MEDIUM – Review recommended

    - HIGH – Immediate attention required

---

## 🧠 Example Output (JSON)
```json
{
  "summary": {
    "HIGH": 2,
    "MEDIUM": 3,
    "LOW": 5
  },
  "findings": [
    {
      "type": "port",
      "risk": "HIGH",
      "risk_score": 5,
      "description": "Open port 22 on 192.168.1.1 running ssh.",
      "mitigation": "Restrict access or secure the exposed service."
    }
  ]
}
```
## 🧹 Graceful Exit

**The tool safely handles:**

- Ctrl + C interruption

- Active threads cleanup

- Partial execution recovery
---
## 🔐 Legal Disclaimer

This tool is intended only for authorized security testing and educational purposes.
The author is not responsible for misuse.
## 📌 Future Improvements

- Markdown report support

- CVSS‑based scoring

- Plugin system for additional recon tools

- AI‑generated executive summaries
