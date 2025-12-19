#!/usr/bin/env python3
"""
Reconnaissance Tool - Final Review Fixes
Issues Fixed:
1. Missing imports added
2. Root check for SYN scan
3. Minor improvements
"""

import os
import sys
import subprocess
import shutil
import logging
import argparse
import shlex
import time
from pathlib import Path
from typing import List, Tuple

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger(__name__)

class ReconTool:
    def __init__(self, domain: str, threads: int = 10, full_scan: bool = False, scan_type: str = "safe"):
        self.domain = domain
        self.threads = threads
        self.full_scan = full_scan
        self.scan_type = scan_type
        
        # Validate domain
        if "." not in self.domain:
            logger.error("Invalid domain name")
            sys.exit(1)
            
        self.tools = {
            'subfinder': shutil.which('subfinder'),
            'amass': shutil.which('amass'),
            'dnsx': shutil.which('dnsx'),
            'httpx': shutil.which('httpx'),
            'nmap': shutil.which('nmap')
        }
        self._validate_tools()
        self.output_dir = f"recon_{int(time.time())}"
        Path(self.output_dir).mkdir(exist_ok=True)
    
    def _validate_tools(self):
        """Validate all required tools are available."""
        missing = [tool for tool, path in self.tools.items() if not path]
        if missing:
            logger.error(f"Missing required tools: {', '.join(missing)}")
            sys.exit(1)
    
    def _run_cmd(self, cmd: str) -> str:
        """Run command safely with shlex parsing."""
        try:
            parsed_cmd = shlex.split(cmd)
            result = subprocess.run(
                parsed_cmd,
                capture_output=True,
                text=True,
                timeout=300
            )
            if result.returncode != 0:
                logger.warning(f"Command failed: {cmd}")
                return ""
            return result.stdout
        except subprocess.TimeoutExpired:
            logger.warning(f"Command timed out: {cmd}")
            return ""
        except Exception as e:
            logger.error(f"Error running command: {e}")
            return ""
    
    def collect_subdomains(self) -> List[str]:
        """Collect subdomains using multiple methods."""
        logger.info(f"Collecting subdomains for {self.domain}...")
        
        # Passive methods
        subfinder_cmd = f"{self.tools['subfinder']} -d {self.domain} -all -t {self.threads}"
        subfinder_out = self._run_cmd(subfinder_cmd)
        
        amass_cmd = f"{self.tools['amass']} enum -passive -d {self.domain} -timeout 5"
        amass_out = self._run_cmd(amass_cmd)
        
        # Active method (optional)
        if self.full_scan:
            active_cmd = f"{self.tools['amass']} enum -active -d {self.domain} -timeout 5"
            active_out = self._run_cmd(active_cmd)
        else:
            active_out = ""
        
        # Combine and deduplicate
        all_subs = set()
        if subfinder_out:
            all_subs.update(subfinder_out.splitlines())
        if amass_out:
            all_subs.update(amass_out.splitlines())
        if active_out:
            all_subs.update(active_out.splitlines())
            
        logger.info(f"Found {len(all_subs)} unique subdomains")
        return list(all_subs)
    
    def verify_live(self, subdomains: List[str]) -> List[str]:
        """Verify which subdomains are alive."""
        logger.info("Verifying live subdomains...")
        
        # Write to temp file
        subs_file = f"{self.output_dir}/subs.txt"
        with open(subs_file, "w") as f:
            f.write("\n".join(subdomains))
        
        # Use dnsx with threads
        dnsx_cmd = f"{self.tools['dnsx']} -l {subs_file} -resp-only -t {self.threads}"
        dnsx_out = self._run_cmd(dnsx_cmd)
        
        if dnsx_out:
            # Deduplicate live subdomains
            live_subs = list(set(dnsx_out.splitlines()))
            logger.info(f"{len(live_subs)} subdomains are alive")
            return live_subs
        return []
    
    def check_ports(self, subdomains: List[str]) -> bool:
        """Check open ports on live subdomains."""
        logger.info("Checking open ports...")
        
        # Write to temp file
        subs_file = f"{self.output_dir}/live_subs.txt"
        with open(subs_file, "w") as f:
            f.write("\n".join(subdomains))
        
        # Determine scan type
        if self.scan_type == "safe":
            scan_opts = "-sT"  # Safe TCP connect scan
        else:
            scan_opts = "-sS"  # SYN scan (requires root)
            
        # Check for root privileges for SYN scan
        if self.scan_type == "syn" and os.geteuid() != 0:
            logger.error("SYN scan requires root privileges")
            return False
            
        # Run nmap with safer ports
        if self.full_scan:
            ports = "-p-"
        else:
            ports = "-p 80,443,22,25,3306,8080"
            
        nmap_cmd = f"{self.tools['nmap']} {scan_opts} --open {ports} -T4 -iL {subs_file} -oA {self.output_dir}/ports"
        result = self._run_cmd(nmap_cmd)
        
        if result:
            logger.info("Port scanning completed")
            return True
        return False
    
    def check_http(self, subdomains: List[str]) -> List[str]:
        """Check HTTP response codes."""
        logger.info("Checking HTTP status codes...")
        
        # Write to temp file
        subs_file = f"{self.output_dir}/live_subs.txt"
        with open(subs_file, "w") as f:
            f.write("\n".join(subdomains))
        
        # Use httpx with threads
        httpx_cmd = f"{self.tools['httpx']} -l {subs_file} -status-code -no-color -threads {self.threads}"
        result = self._run_cmd(httpx_cmd)
        
        if result:
            return result.splitlines()
        return []
    
    def classify_responses(self, http_responses: List[str]) -> Tuple[List[str], List[str]]:
        """Classify responses by status code."""
        logger.info("Classifying responses...")
        
        four_xx = []
        five_xx = []
        
        for line in http_responses:
            try:
                # Extract status code from brackets
                status = line.split("[")[-1].strip("]")
                domain = line.split()[0]
                
                if status.startswith("4"):
                    four_xx.append(f"{domain} ({status})")
                elif status.startswith("5"):
                    five_xx.append(f"{domain} ({status})")
            except:
                logger.warning(f"Failed to parse response: {line}")
        
        return four_xx, five_xx
    
    def save_results(self, four_xx: List[str], five_xx: List[str]):
        """Save results to files."""
        with open(f"{self.output_dir}/4xx.txt", "w") as f:
            f.write("\n".join(four_xx))
            
        with open(f"{self.output_dir}/5xx.txt", "w") as f:
            f.write("\n".join(five_xx))
            
        with open(f"{self.output_dir}/full_report.txt", "w") as f:
            f.write("=== 4XX Response Domains ===\n")
            f.write("\n".join(four_xx))
            f.write("\n\n=== 5XX Response Domains ===\n")
            f.write("\n".join(five_xx))
            
        logger.info(f"Results saved to {self.output_dir}/")
    
    def cleanup(self):
        """Clean up temporary files."""
        try:
            os.remove(f"{self.output_dir}/subs.txt")
            os.remove(f"{self.output_dir}/live_subs.txt")
        except:
            pass
    
    def run(self):
        """Run the complete reconnaissance workflow."""
        try:
            # Collect subdomains
            subdomains = self.collect_subdomains()
            if not subdomains:
                return
                
            # Verify live subdomains
            live_subs = self.verify_live(subdomains)
            if not live_subs:
                return
                
            # Check ports
            if not self.check_ports(live_subs):
                return
                
            # Check HTTP responses
            http_responses = self.check_http(live_subs)
            
            # Classify responses
            four_xx, five_xx = self.classify_responses(http_responses)
            
            # Save results
            self.save_results(four_xx, five_xx)
        finally:
            self.cleanup()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Reconnaissance Tool")
    parser.add_argument("-d", "--domain", required=True, help="Target domain")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Number of threads")
    parser.add_argument("--full-scan", action="store_true", help="Full port scan")
    parser.add_argument("--scan-type", choices=["safe", "syn"], default="safe", 
                       help="Scan type: safe (TCP) or syn (requires root)")
    args = parser.parse_args()
    
    try:
        scanner = ReconTool(args.domain, args.threads, args.full_scan, args.scan_type)
        scanner.run()
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
        sys.exit(1)
