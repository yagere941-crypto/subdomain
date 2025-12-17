# ReconTool

## Description
ReconTool is a Python-based reconnaissance automation tool built to support early-stage security assessments. It consolidates common reconnaissance tasks—subdomain discovery, host validation, port scanning, and HTTP response analysis—into a single, repeatable workflow. The tool is designed to reduce manual overhead during initial recon while keeping results structured, traceable, and suitable for authorized testing environments.

This project was created to better understand how professional reconnaissance pipelines are built and how different tools integrate during real-world security assessments.

## Design Philosophy
- Focus on **accuracy and clarity**, not exploitation
- Use **well-known, trusted tools** instead of custom scanners
- Keep defaults **safe and conservative**
- Produce outputs that are easy to review and audit
- Emphasize learning, repeatability, and responsible use

## Features
- Subdomain enumeration using **subfinder** and **amass** (passive and active techniques)
- Live host validation with **dnsx**
- TCP connect-based port scanning using **nmap**
- HTTP and HTTPS probing with **httpx**
- Automatic classification of HTTP responses (4XX and 5XX)
- Threaded execution to improve efficiency on larger scopes
- Organized output files for further manual or automated analysis

## Workflow Overview
1. Enumerate subdomains for the given target
2. Filter and validate live hosts via DNS resolution
3. Identify exposed services through safe TCP port scans
4. Probe HTTP services and collect response status codes
5. Separate and store results for focused review

## Requirements
- Python 3.9 or newer
- subfinder
- amass
- dnsx
- nmap
- httpx

All external tools must be installed separately and accessible via the system `$PATH`.

## Usage
```bash
python3 recontol.py -d example.com -o output/
```

## Output Files

- subdomains.txt
All discovered subdomains collected from passive and active sources.

- live_hosts.txt
Subdomains that successfully resolved and responded during validation.

- open_ports.txt
Open TCP ports detected on live hosts using nmap.

- http_4xx.txt
HTTP endpoints returning client-side error responses.

- http_5xx.txt
HTTP endpoints returning server-side error responses.

---

Output structure may vary slightly depending on flags and scope size.

---

## Limitations

- This tool does not perform exploitation or vulnerability verification

- Service and version detection are intentionally limited

- Results should always be manually reviewed and validated

- It is not intended to replace advanced frameworks or scanners

## Ethical Notice

This tool is intended strictly for educational purposes and authorized security testing. Use only against systems you own or have explicit permission to test. Unauthorized scanning may be illegal and unethical. The author assumes no responsibility for misuse.

## Author Notes

ReconTool was developed as a learning project to understand reconnaissance workflows, tool chaining, and automation in offensive security. It reflects real-world practices while maintaining a strong focus on ethics and responsibility.
