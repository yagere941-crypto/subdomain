#!/usr/bin/env python3
"""
AI-Assisted Recon Notes Generator
Parses outputs from subfinder, httpx, and nmap tools
Generates structured reports with risk analysis
"""

import argparse
import json
import os
import sys
import signal
import time
import xml.etree.ElementTree as ET
from typing import List, Dict, Any

# Global tracking for multi-threaded cleanup
active_threads = []

# Signal handler for Ctrl+C
def signal_handler(sig, frame):
    print('\nExiting gracefully...')
    cleanup_threads()
    sys.exit(0)

# Thread cleanup function (to be called on exit)
def cleanup_threads():
    for thread in active_threads:
        thread.join(timeout=1)
        if thread.is_alive():
            print(f"WARNING: Thread {thread.name} still running")

# Parser functions
def parse_subfinder(file_path: str) -> List[Dict[str, Any]]:
    """Parse subfinder TXT output."""
    findings = []
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            for line in f:
                domain = line.strip()
                if '.' in domain:
                    findings.append({
                        'type': 'subdomain',
                        'value': domain
                    })
    except FileNotFoundError:
        print(f"ERROR: File '{file_path}' not found")
        sys.exit(1)
    except PermissionError:
        print(f"ERROR: Permission denied accessing '{file_path}'")
        sys.exit(1)
    return findings

def parse_httpx(file_path: str) -> List[Dict[str, Any]]:
    """Parse httpx JSON lines output."""
    findings = []
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            for i, line in enumerate(f):
                try:
                    item = json.loads(line)
                    findings.append({
                        'type': 'url',
                        'value': item.get('url'),
                        'status_code': item.get('status_code'),
                        'technology': item.get('tech', []),
                        'waf_detected': item.get('waf', False)
                    })
                except json.JSONDecodeError:
                    print(f"WARNING: Skipping malformed JSON line {i+1}")
                    continue
    except FileNotFoundError:
        print(f"ERROR: File '{file_path}' not found")
        sys.exit(1)
    except PermissionError:
        print(f"ERROR: Permission denied accessing '{file_path}'")
        sys.exit(1)
    return findings

def parse_nmap(file_path: str) -> List[Dict[str, Any]]:
    """Parse nmap XML output."""
    findings = []
    try:
        tree = ET.parse(file_path)
        root = tree.getroot()
        
        # Validate basic XML structure
        if root.tag != 'nmaprun':
            print(f"WARNING: Invalid XML format in '{file_path}'")
            raise ValueError("Invalid XML structure")
            
        for host in root.findall('host'):
            ip = host.find('address').get('addr') if host.find('address') is not None else 'unknown'
            for port in host.findall('.//port'):
                state = port.find('state')
                if state is not None and state.get('state') == 'open':
                    service = port.find('service')
                    findings.append({
                        'type': 'port',
                        'host': ip,
                        'port': int(port.get('portid')),
                        'protocol': port.get('protocol'),
                        'service': service.get('name') if service is not None else 'unknown'
                    })
    except ET.ParseError as e:
        print(f"ERROR: Invalid XML format in '{file_path}': {str(e)}")
        sys.exit(1)
    except FileNotFoundError:
        print(f"ERROR: File '{file_path}' not found")
        sys.exit(1)
    except PermissionError:
        print(f"ERROR: Permission denied accessing '{file_path}'")
        sys.exit(1)
    return findings

# Analyzer class
class SecurityAnalyzer:
    """Analyze findings and assign risk levels."""
    
    def analyze_findings(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Analyze all findings and assign risk levels."""
        analyzed = []
        for f in findings:
            risk_level, score = self._risk_level(f)
            analyzed.append({
                'finding': f,
                'risk_level': risk_level,
                'risk_score': score,
                'explanation': self._explain(f),
                'mitigation': self._mitigation(f)
            })
        return analyzed

    def _risk_level(self, f: Dict[str, Any]) -> tuple:
        """Calculate risk level and numeric score."""
        score = 0
        
        if f.get('type') == 'port':
            if f.get('port', 0) < 1024:
                score += 3
            else:
                score += 2
                
        if f.get('type') == 'subdomain':
            if any(x in f.get('value', '') for x in ['admin', 'dev', 'test']):
                score += 2
                
        if f.get('type') == 'url':
            if not f.get('waf_detected', True):
                score += 2
            if 500 <= f.get('status_code', 0) < 600:
                score += 1
                
        risk_level = 'HIGH' if score >= 5 else 'MEDIUM' if score >= 3 else 'LOW'
        return risk_level, score

    def _explain(self, f: Dict[str, Any]) -> str:
        """Generate explanation for finding."""
        if f.get('type') == 'subdomain':
            return f"Subdomain `{f.get('value')}` is publicly accessible."
        if f.get('type') == 'port':
            return f"Open port {f.get('port')} on {f.get('host')} running {f.get('service')}."
        if f.get('type') == 'url':
            return f"Accessible URL `{f.get('value')}` detected (Status: {f.get('status_code')})." 
        return "Recon finding identified."

    def _mitigation(self, f: Dict[str, Any]) -> str:
        """Generate mitigation for finding."""
        if f.get('type') == 'port':
            return "Restrict access or secure the exposed service."
        if f.get('type') == 'subdomain':
            return "Review exposure and restrict unnecessary access."
        if f.get('type') == 'url' and not f.get('waf_detected', True):
            return "Enable a Web Application Firewall (WAF)."
        return "Review security configuration."

# Formatter function
def format_notes(analyzed: List[Dict[str, Any]], format_type: str = "json") -> Dict[str, Any]:
    """Format analyzed findings into structured report."""
    # Sort findings by risk score (highest first)
    analyzed.sort(key=lambda x: x["risk_score"], reverse=True)
    
    output = {
        'summary': {'HIGH': 0, 'MEDIUM': 0, 'LOW': 0},
        'findings': []
    }

    for item in analyzed:
        output['summary'][item['risk_level']] += 1
        output['findings'].append({
            'type': item['finding']['type'],
            'risk': item['risk_level'],
            'risk_score': item['risk_score'],
            'description': item['explanation'],
            'mitigation': item['mitigation']
        })

    return output

# Main function
def main():
    """Main function for CLI interface."""
    # Register signal handler for Ctrl+C
    signal.signal(signal.SIGINT, signal_handler)
    
    parser = argparse.ArgumentParser(
        description="AI-Assisted Recon Notes Generator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py --input subdomains.txt --output report.json
  python main.py --input results.json
  python main.py --input nmap.xml --output findings.json
        """
    )
    parser.add_argument(
        "--input", 
        required=True, 
        help="Input file path (.txt, .json, .xml)"
    )
    parser.add_argument(
        "--output", 
        default="recon_notes.json", 
        help="Output JSON file"
    )
    parser.add_argument(
        "--format", 
        choices=["json", "html", "csv"], 
        default="json",
        help="Output format (default: json)"
    )
    args = parser.parse_args()

    if not os.path.exists(args.input):
        print(f"ERROR: Input file '{args.input}' not found")
        sys.exit(1)

    # Validate output path
    output_dir = os.path.dirname(os.path.abspath(args.output))
    if output_dir and not os.path.exists(output_dir):
        print(f"ERROR: Output directory '{output_dir}' does not exist")
        sys.exit(1)
    
    start_time = time.time()
    
    try:
        ext = os.path.splitext(args.input)[1].lower()
        if ext == ".txt":
            findings = parse_subfinder(args.input)
        elif ext == ".json":
            findings = parse_httpx(args.input)
        elif ext == ".xml":
            findings = parse_nmap(args.input)
        else:
            print(f"ERROR: Unsupported file type '{ext}'. Supported: .txt, .json, .xml")
            sys.exit(1)
            
        print(f"Found {len(findings)} findings")
        
        analyzer = SecurityAnalyzer()
        analyzed = analyzer.analyze_findings(findings)
        
        notes = format_notes(analyzed, args.format)
        
        # Write output file
        with open(args.output, "w") as f:
            if args.format == "json":
                json.dump(notes, f, indent=2)
            elif args.format == "csv":
                # Simple CSV export
                f.write("Risk,Type,Description,Mitigation\n")
                for item in notes['findings']:
                    f.write(f"{item['risk']},{item['type']},{item['description']},{item['mitigation']}\n")
            elif args.format == "html":
                # Simple HTML export
                f.write("<html><body>\n")
                f.write("<h1>Recon Notes</h1>\n")
                f.write("<table border='1'><tr><th>Risk</th><th>Type</th><th>Description</th><th>Mitigation</th></tr>\n")
                for item in notes['findings']:
                    f.write(f"<tr><td>{item['risk']}</td><td>{item['type']}</td><td>{item['description']}</td><td>{item['mitigation']}</td></tr>\n")
                f.write("</table>\n</body></html>")
        
        elapsed = time.time() - start_time
        print(f"[+] Report generated: {args.output} ({elapsed:.2f}s)")
        
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user")
        cleanup_threads()
        sys.exit(0)
    except Exception as e:
        print(f"ERROR: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()