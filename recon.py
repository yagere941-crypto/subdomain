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
from typing import List, Dict, Any, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed
import logging
import traceback
from datetime import datetime
from dataclasses import dataclass, field
from enum import Enum

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('recon_notes.log'),
        logging.StreamHandler(sys.stdout)
    ]
)

# Risk thresholds configuration
RISK_THRESHOLDS = {
    'high': 5,
    'medium': 3,
    'low': 0
}

# Enums for risk levels
class RiskLevel(Enum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3

# Data classes for findings
@dataclass
class Finding:
    type: str
    value: str
    metadata: Dict[str, Any] = field(default_factory=dict)
    risk_level: RiskLevel = field(default=RiskLevel.LOW)
    risk_score: int = field(default=0)
    explanations: List[str] = field(default_factory=list)
    mitigations: List[str] = field(default_factory=list)

@dataclass
class AnalysisResult:
    findings: List[Finding] = field(default_factory=list)
    summary: Dict[RiskLevel, int] = field(default_factory=dict)

# Parser functions
def parse_subfinder(file_path: str) -> List[Finding]:
    """Parse subfinder TXT output."""
    findings = []
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            for line in f:
                domain = line.strip()
                if '.' in domain:
                    findings.append(Finding(
                        type='subdomain',
                        value=domain
                    ))
    except FileNotFoundError:
        logging.error(f"File '{file_path}' not found")
        raise
    except PermissionError:
        logging.error(f"Permission denied accessing '{file_path}'")
        raise
    return findings

def parse_httpx(file_path: str) -> List[Finding]:
    """Parse httpx JSON lines output."""
    findings = []
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            for i, line in enumerate(f):
                try:
                    item = json.loads(line)
                    url = item.get('url')
                    if url is None:
                        logging.warning(f"Skipping entry with missing URL at line {i+1}")
                        continue
                    
                    findings.append(Finding(
                        type='url',
                        value=url,
                        metadata={
                            'status_code': item.get('status_code'),
                            'technology': item.get('tech', []),
                            'waf_detected': item.get('waf', False)
                        }
                    ))
                except json.JSONDecodeError:
                    logging.warning(f"Skipping malformed JSON line {i+1}")
                    continue
    except FileNotFoundError:
        logging.error(f"File '{file_path}' not found")
        raise
    except PermissionError:
        logging.error(f"Permission denied accessing '{file_path}'")
        raise
    return findings

def parse_nmap(file_path: str) -> List[Finding]:
    """Parse nmap XML output."""
    findings = []
    try:
        tree = ET.parse(file_path)
        root = tree.getroot()
        
        # Validate basic XML structure
        if root.tag != 'nmaprun':
            logging.warning(f"Invalid XML format in '{file_path}'")
            raise ValueError("Invalid XML structure")
            
        for host in root.findall('host'):
            ip = host.find('address').get('addr') if host.find('address') is not None else 'unknown'
            for port in host.findall('.//port'):
                state = port.find('state')
                if state is not None and state.get('state') == 'open':
                    service = port.find('service')
                    port_id = port.get('portid')
                    if port_id is None:
                        logging.warning(f"Skipping entry with missing port ID")
                        continue
                    
                    findings.append(Finding(
                        type='port',
                        value=f"{ip}:{port_id}",
                        metadata={
                            'host': ip,
                            'port': int(port_id),
                            'protocol': port.get('protocol'),
                            'service': service.get('name') if service is not None else 'unknown'
                        }
                    ))
    except ET.ParseError as e:
        logging.error(f"Invalid XML format in '{file_path}': {str(e)}")
        raise
    except FileNotFoundError:
        logging.error(f"File '{file_path}' not found")
        raise
    except PermissionError:
        logging.error(f"Permission denied accessing '{file_path}'")
        raise
    return findings

# Normalization layer
def normalize_finding(finding: Finding) -> Finding:
    """Normalize finding to ensure consistent structure."""
    # Ensure required fields are present
    if finding.value is None:
        finding.value = "Unknown"
    
    # Ensure metadata is always a dict
    if not isinstance(finding.metadata, dict):
        finding.metadata = {}
    
    # Ensure explanations and mitigations are lists
    if not isinstance(finding.explanations, list):
        finding.explanations = [finding.explanations]
    if not isinstance(finding.mitigations, list):
        finding.mitigations = [finding.mitigations]
    
    return finding

# Risk scoring plugins
class RiskScoringPlugin:
    def calculate_score(self, finding: Finding) -> Tuple[int, List[str]]:
        """Calculate risk score and explanation for a finding."""
        score = 0
        explanations = []
        
        if finding.type == 'port':
            port = finding.metadata.get('port', 0)
            if port < 1024:
                score += 3
                explanations.append(f"Privileged port {port} is accessible")
            else:
                score += 2
                explanations.append(f"Non-privileged port {port} is accessible")
                
        if finding.type == 'subdomain':
            if any(x in finding.value for x in ['admin', 'dev', 'test']):
                score += 2
                explanations.append(f"Sensitive subdomain '{finding.value}' is accessible")
                
        if finding.type == 'url':
            status_code = finding.metadata.get('status_code', 0)
            if not finding.metadata.get('waf_detected', True):
                score += 2
                explanations.append("No WAF detected")
            if 500 <= status_code < 600:
                score += 1
                explanations.append(f"Server error (HTTP {status_code})")
                
        return score, explanations

# Analyzer class
class SecurityAnalyzer:
    """Analyze findings and assign risk levels."""
    
    def __init__(self, plugins: List[RiskScoringPlugin]):
        self.plugins = plugins
    
    def analyze_findings(self, findings: List[Finding]) -> AnalysisResult:
        """Analyze all findings and assign risk levels."""
        analyzed = []
        summary = {level: 0 for level in RiskLevel}
        
        for f in findings:
            normalized_finding = normalize_finding(f)
            total_score = 0
            explanations = []
            mitigations = []
            
            for plugin in self.plugins:
                score, plugin_explanations = plugin.calculate_score(normalized_finding)
                total_score += score
                explanations.extend(plugin_explanations)
            
            risk_level = RiskLevel.HIGH if total_score >= RISK_THRESHOLDS['high'] else \
                         RiskLevel.MEDIUM if total_score >= RISK_THRESHOLDS['medium'] else \
                         RiskLevel.LOW
            
            normalized_finding.risk_level = risk_level
            normalized_finding.risk_score = total_score
            normalized_finding.explanations = explanations
            normalized_finding.mitigations = ["Review security configuration"]
            
            analyzed.append(normalized_finding)
            summary[risk_level] += 1
        
        return AnalysisResult(findings=analyzed, summary=summary)

# Formatter function
def format_notes(result: AnalysisResult, format_type: str = "json") -> str:
    """Format analyzed findings into structured report."""
    # Sort findings by risk level (HIGH → LOW)
    result.findings.sort(key=lambda x: x.risk_level.value, reverse=True)
    
    output = {
        'timestamp': datetime.now().isoformat(),
        'summary': {level.name: count for level, count in result.summary.items()},
        'total_findings': len(result.findings),
        'findings': []
    }

    for item in result.findings:
        output['findings'].append({
            'type': item.type,
            'value': item.value,
            'risk': item.risk_level.name,
            'risk_score': item.risk_score,
            'explanations': item.explanations,
            'mitigations': item.mitigations,
            'metadata': item.metadata
        })

    if format_type == "json":
        return json.dumps(output, indent=2)
    elif format_type == "csv":
        # Simple CSV export
        csv_data = "Risk,Type,Value,Explanation,Mitigation\n"
        for item in output['findings']:
            csv_data += f"{item['risk']},{item['type']},{item['value']},{','.join(item['explanations'])},{','.join(item['mitigations'])}\n"
        return csv_data
    elif format_type == "html":
        # Professional HTML export
        html_data = "<html><head><title>Recon Notes</title><style>body {font-family: Arial, sans-serif; margin: 20px;} h1 {color: #333; border-bottom: 1px solid #ccc; padding-bottom: 10px;} .summary {display: flex; justify-content: space-around; margin: 20px 0; padding: 10px; background-color: #f5f5f5; border-radius: 5px;} .card {text-align: center; padding: 10px; border-radius: 5px; font-weight: bold;} .high {background-color: #ffdddd; color: #d00;}.medium {background-color: #ffffdd; color: #dd0;}.low {background-color: #ddffdd; color: #0d0;}.findings {margin-top: 20px;} table {width: 100%; border-collapse: collapse; margin-top: 10px;} th, td {padding: 10px; border: 1px solid #ddd; text-align: left;}</style></head><body>\n"
        html_data += "<h1>Recon Notes</h1>\n"
        html_data += "<div class='summary'>\n"
        for level, count in output['summary'].items():
            level_class = level.lower()
            html_data += f"<div class='card {level_class}'>{level}: {count}</div>\n"
        html_data += "</div>\n"
        html_data += f"<p><strong>Total Findings:</strong> {output['total_findings']}</p>\n"
        html_data += f"<p><strong>Generated At:</strong> {output['timestamp']}</p>\n"
        
        # Group findings by risk level
        for level in sorted(RiskLevel, key=lambda x: x.value, reverse=True):
            level_findings = [f for f in output['findings'] if f['risk'] == level.name]
            if level_findings:
                html_data += f"<h2>{level.name} Findings</h2>\n"
                html_data += "<div class='findings'>\n"
                html_data += "<table>\n"
                html_data += "<tr><th>Risk</th><th>Type</th><th>Value</th><th>Explanation</th><th>Mitigation</th></tr>\n"
                for item in level_findings:
                    level_class = level.name.lower()
                    html_data += f"<tr class='{level_class}'><td>{item['risk']}</td><td>{item['type']}</td><td>{item['value']}</td><td>{'<br>'.join(item['explanations'])}</td><td>{'<br>'.join(item['mitigations'])}</td></tr>\n"
                html_data += "</table>\n</div>\n"
        
        html_data += "</body></html>"
        return html_data
    else:
        raise ValueError(f"Unsupported format type: {format_type}")

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
    parser.add_argument(
        "--verbose", 
        action="store_true",
        help="Enable verbose logging"
    )
    parser.add_argument(
        "--version", 
        action="version",
        version="1.0.0",
        help="Show version and exit"
    )
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    if not os.path.exists(args.input):
        logging.error(f"Input file '{args.input}' not found")
        sys.exit(2)

    # Validate output path
    output_dir = os.path.dirname(os.path.abspath(args.output))
    if output_dir and not os.path.exists(output_dir):
        logging.error(f"Output directory '{output_dir}' does not exist")
        sys.exit(2)
    
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
            logging.error(f"Unsupported file type '{ext}'. Supported: .txt, .json, .xml")
            sys.exit(2)
            
        logging.info(f"Found {len(findings)} findings")
        
        analyzer = SecurityAnalyzer([RiskScoringPlugin()])
        result = analyzer.analyze_findings(findings)
        
        formatted_output = format_notes(result, args.format)
        
        # Write output file
        with open(args.output, "w") as f:
            f.write(formatted_output)
        
        elapsed = time.time() - start_time
        logging.info(f"Report generated: {args.output} ({elapsed:.2f}s)")
        
        sys.exit(0)
        
    except KeyboardInterrupt:
        logging.warning("Interrupted by user")
        sys.exit(0)
    except Exception as e:
        logging.error(str(e))
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
