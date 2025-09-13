#!/usr/bin/env python3
"""
NO REGRESSH - Network Scanner Module
Advanced scanner functionality with multi-threading and detailed reporting
"""

import socket
import threading
import time
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Tuple
from dataclasses import dataclass
import csv
from datetime import datetime

from no_regresh_main import NoRegreshFramework, StatusLevel, Colors

@dataclass
class ScanResult:
    ip: str
    port: int
    is_ssh: bool
    vulnerabilities: Dict[str, bool]
    banner: str
    response_time: float
    scan_timestamp: str
    cve_details: Dict[str, str]

class NetworkScanner:
    def __init__(self, framework: NoRegreshFramework):
        self.framework = framework
        self.results = []
        self.vulnerable_count = 0
        self.scan_lock = threading.Lock()
        
    def scan_ip_range(self, start_ip: str, end_ip: str, port: int = 22, 
                     max_threads: int = 20, scan_cves: List[str] = None) -> List[ScanResult]:
        """Scan IP range with multi-threading and CVE detection"""
        
        if scan_cves is None:
            scan_cves = ["CVE-2024-6387", "CVE-2020-14145", "CVE-2021-28041", "CVE-2019-16905", "CVE-2018-15473"]
        
        self.framework.print_status(StatusLevel.INFO, 
            f"Starting network scan from {start_ip} to {end_ip} on port {port}")
        self.framework.print_status(StatusLevel.INFO, 
            f"Scanning for CVEs: {', '.join(scan_cves)}")
        
        # Validate IPs
        try:
            start_addr = ipaddress.ip_address(start_ip)
            end_addr = ipaddress.ip_address(end_ip)
        except ValueError as e:
            self.framework.print_status(StatusLevel.ERROR, f"Invalid IP address: {e}")
            return []
            
        # Generate IP list
        ip_list = []
        current = start_addr
        
        while current <= end_addr:
            ip_list.append(str(current))
            current += 1
            
        total_ips = len(ip_list)
        self.framework.print_status(StatusLevel.INFO, 
            f"Scanning {total_ips} IP addresses with {max_threads} threads")
        
        # Threading setup
        results = []
        completed = 0
        
        with ThreadPoolExecutor(max_workers=max_threads) as executor:
            # Submit all scan tasks
            future_to_ip = {
                executor.submit(self._scan_single_ip, ip, port, scan_cves): ip 
                for ip in ip_list
            }
            
            # Collect results
            for future in as_completed(future_to_ip):
                ip = future_to_ip[future]
                try:
                    result = future.result()
                    if result:
                        results.append(result)
                        if any(result.vulnerabilities.values()):
                            with self.scan_lock:
                                self.vulnerable_count += 1
                                
                except Exception as e:
                    self.framework.print_status(StatusLevel.ERROR, 
                        f"Error scanning {ip}: {e}")
                
                completed += 1
                self.framework.print_progress_bar(completed, total_ips, "Scan Progress")
                
        print()  # New line after progress bar
        
        self.framework.print_status(StatusLevel.SUCCESS, 
            f"Scan completed: {len(results)} SSH services found, "
            f"{self.vulnerable_count} vulnerable")
            
        return results
        
    def _scan_single_ip(self, ip: str, port: int, scan_cves: List[str]) -> ScanResult:
        """Scan single IP address"""
        is_ssh, banner, response_time = self.framework.grab_ssh_banner(ip, port)
        
        if is_ssh:
            vulnerabilities = self.framework.check_ssh_vulnerability(banner)
            
            # Filter vulnerabilities based on scan_cves
            filtered_vulnerabilities = {cve: vulnerabilities.get(cve, False) for cve in scan_cves}
            
            # Generate CVE details
            cve_details = self._generate_cve_details(banner, filtered_vulnerabilities)
            
            result = ScanResult(
                ip=ip,
                port=port,
                is_ssh=is_ssh,
                vulnerabilities=filtered_vulnerabilities,
                banner=banner,
                response_time=response_time,
                scan_timestamp=datetime.now().isoformat(),
                cve_details=cve_details
            )
            
            # Status message
            vulnerable_cves = [cve for cve, vuln in filtered_vulnerabilities.items() if vuln]
            if vulnerable_cves:
                self.framework.print_status(StatusLevel.VULN, 
                    f"VULNERABLE: {ip}:{port} - {', '.join(vulnerable_cves)} ({response_time:.1f}ms)")
            else:
                self.framework.print_status(StatusLevel.INFO, 
                    f"SSH found: {ip}:{port} - {banner[:50]}... ({response_time:.1f}ms)")
                    
            return result
            
        return None
        
    def _generate_cve_details(self, banner: str, vulnerabilities: Dict[str, bool]) -> Dict[str, str]:
        """Generate detailed CVE information"""
        cve_details = {}
        
        for cve, is_vulnerable in vulnerabilities.items():
            if is_vulnerable:
                if cve == "CVE-2024-6387":
                    cve_details[cve] = "Remote Code Execution via Signal Handler Race Condition"
                elif cve == "CVE-2020-14145":
                    cve_details[cve] = "Username Enumeration via Timing Attack"
                elif cve == "CVE-2021-28041":
                    cve_details[cve] = "Username Enumeration via Response Timing"
                elif cve == "CVE-2019-16905":
                    cve_details[cve] = "Username Enumeration via Error Messages"
                elif cve == "CVE-2018-15473":
                    cve_details[cve] = "Username Enumeration via Response Differences"
            else:
                cve_details[cve] = "Not vulnerable"
                
        return cve_details
        
    def scan_single_target(self, ip: str, port: int = 22, scan_cves: List[str] = None) -> ScanResult:
        """Scan single target"""
        if scan_cves is None:
            scan_cves = ["CVE-2024-6387", "CVE-2020-14145", "CVE-2021-28041", "CVE-2019-16905", "CVE-2018-15473"]
            
        self.framework.print_status(StatusLevel.INFO, f"Scanning target {ip}:{port}")
        
        # Check reachability
        if not self.framework.check_ip_reachability(ip, port):
            self.framework.print_status(StatusLevel.WARN, 
                f"Target {ip}:{port} is not reachable")
            return None
            
        return self._scan_single_ip(ip, port, scan_cves)
        
    def display_results(self, results: List[ScanResult]):
        """Display scan results in organized format"""
        if not results:
            self.framework.print_status(StatusLevel.WARN, "No results to display")
            return
            
        print(f"\n{Colors.BOLD}╔═══════════════ Scan Results ═══════════════╗{Colors.RESET}")
        print(f"║ SSH Services Found: {len(results):3d}                   ║")
        
        # Count vulnerabilities
        vuln_counts = {}
        for result in results:
            for cve, is_vuln in result.vulnerabilities.items():
                if is_vuln:
                    vuln_counts[cve] = vuln_counts.get(cve, 0) + 1
                    
        print(f"║ Vulnerable Services: {sum(vuln_counts.values()):3d}                   ║")
        print(f"╚═══════════════════════════════════════════════╝\n")
        
        # Detailed table
        print(f"{Colors.BOLD}Detailed Results:{Colors.RESET}")
        print(f"{'IP':<15} {'Port':<6} {'Vulnerable':<12} {'Time(ms)':<8} {'CVEs':<30} {'Banner'}")
        print("─" * 100)
        
        for result in results:
            vulnerable_cves = [cve for cve, vuln in result.vulnerabilities.items() if vuln]
            vuln_status = f"{Colors.RED}YES{Colors.RESET}" if vulnerable_cves else f"{Colors.GREEN}NO{Colors.RESET}"
            cve_list = ", ".join(vulnerable_cves) if vulnerable_cves else "None"
            
            print(f"{result.ip:<15} {result.port:<6} {vuln_status:<12} "
                  f"{result.response_time:<8.1f} {cve_list:<30} {result.banner[:30]}")
                  
        # Vulnerability summary
        if vuln_counts:
            print(f"\n{Colors.BOLD}Vulnerability Summary:{Colors.RESET}")
            for cve, count in vuln_counts.items():
                print(f"  {Colors.RED}• {cve}: {count} targets{Colors.RESET}")
                
    def export_results(self, results: List[ScanResult], filename: str = None):
        """Export results as CSV"""
        if not results:
            self.framework.print_status(StatusLevel.WARN, "No results to export")
            return
            
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"scan_results_{timestamp}.csv"
            
        try:
            with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
                fieldnames = ['IP', 'Port', 'IsSSH', 'ResponseTime', 'Banner', 'ScanTimestamp']
                
                # Add CVE columns
                cve_columns = []
                for result in results:
                    for cve in result.vulnerabilities.keys():
                        if cve not in cve_columns:
                            cve_columns.append(cve)
                            
                fieldnames.extend(cve_columns)
                fieldnames.extend(['CVE_Details'])
                
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                
                writer.writeheader()
                for result in results:
                    row = {
                        'IP': result.ip,
                        'Port': result.port,
                        'IsSSH': 'YES' if result.is_ssh else 'NO',
                        'ResponseTime': f"{result.response_time:.2f}",
                        'Banner': result.banner,
                        'ScanTimestamp': result.scan_timestamp
                    }
                    
                    # Add CVE columns
                    for cve in cve_columns:
                        row[cve] = 'YES' if result.vulnerabilities.get(cve, False) else 'NO'
                        
                    # Add CVE details
                    cve_details_str = "; ".join([f"{cve}: {details}" for cve, details in result.cve_details.items()])
                    row['CVE_Details'] = cve_details_str
                    
                    writer.writerow(row)
                    
            self.framework.print_status(StatusLevel.SUCCESS, 
                f"Results exported to {filename}")
                
        except Exception as e:
            self.framework.print_status(StatusLevel.ERROR, 
                f"Error exporting results: {e}")
                
    def interactive_scan(self):
        """Interactive scan mode"""
        print(f"{Colors.BOLD}\n╔═══════════════ Network Scanner ═══════════════╗{Colors.RESET}")
        print("║ SSH Service and Vulnerability Scan Configuration ║")
        print("╚══════════════════════════════════════════════════╝\n")
        
        # IP range input
        start_ip = input("Enter start IP (e.g., 192.168.1.1): ").strip()
        if not self.framework.validate_ip(start_ip):
            self.framework.print_status(StatusLevel.ERROR, "Invalid start IP")
            return []
            
        end_ip = input("Enter end IP (e.g., 192.168.1.254): ").strip()
        if not self.framework.validate_ip(end_ip):
            self.framework.print_status(StatusLevel.ERROR, "Invalid end IP")
            return []
            
        # Port input
        try:
            port = int(input("Port (default: 22): ") or "22")
            if not self.framework.validate_port(port):
                self.framework.print_status(StatusLevel.ERROR, "Invalid port")
                return []
        except ValueError:
            self.framework.print_status(StatusLevel.ERROR, "Invalid port input")
            return []
            
        # Thread count
        try:
            max_threads = int(input("Thread count (1-50, default: 20): ") or "20")
            max_threads = max(1, min(50, max_threads))
        except ValueError:
            max_threads = 20
            
        # CVE selection
        print("\nCVE Selection:")
        print("1) All CVEs (recommended)")
        print("2) CVE-2024-6387 only (regreSSHion)")
        print("3) Username enumeration CVEs only")
        print("4) Custom selection")
        
        try:
            cve_choice = int(input("CVE selection: "))
        except ValueError:
            cve_choice = 1
            
        scan_cves = []
        if cve_choice == 1:
            scan_cves = ["CVE-2024-6387", "CVE-2020-14145", "CVE-2021-28041", "CVE-2019-16905", "CVE-2018-15473"]
        elif cve_choice == 2:
            scan_cves = ["CVE-2024-6387"]
        elif cve_choice == 3:
            scan_cves = ["CVE-2020-14145", "CVE-2021-28041", "CVE-2019-16905", "CVE-2018-15473"]
        elif cve_choice == 4:
            print("\nAvailable CVEs:")
            print("1) CVE-2024-6387 (regreSSHion)")
            print("2) CVE-2020-14145 (username enumeration)")
            print("3) CVE-2021-28041 (username enumeration)")
            print("4) CVE-2019-16905 (username enumeration)")
            print("5) CVE-2018-15473 (username enumeration)")
            
            cve_input = input("Enter CVE numbers (comma-separated, e.g., 1,2,3): ").strip()
            cve_map = {
                "1": "CVE-2024-6387",
                "2": "CVE-2020-14145",
                "3": "CVE-2021-28041",
                "4": "CVE-2019-16905",
                "5": "CVE-2018-15473"
            }
            
            for cve_num in cve_input.split(','):
                cve_num = cve_num.strip()
                if cve_num in cve_map:
                    scan_cves.append(cve_map[cve_num])
        else:
            scan_cves = ["CVE-2024-6387", "CVE-2020-14145", "CVE-2021-28041", "CVE-2019-16905", "CVE-2018-15473"]
            
        # Execute scan
        results = self.scan_ip_range(start_ip, end_ip, port, max_threads, scan_cves)
        
        if results:
            self.display_results(results)
            
            # Export option
            export = input("\nExport results? (y/n): ").lower().strip()
            if export in ['y', 'yes']:
                self.export_results(results)
                
        return results
