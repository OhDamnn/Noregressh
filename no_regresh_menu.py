#!/usr/bin/env python3
"""
NO REGRESSH - Main Menu System
Main menu and user interface for the framework
"""

import os
import sys
from typing import Optional

from no_regresh_main import NoRegreshFramework, StatusLevel, Colors
from no_regresh_scanner import NetworkScanner
from no_regresh_exploit import ExploitManager
from no_regresh_listener import ListenerManager
from no_regresh_system import SystemChecker

class MenuSystem:
    """Main menu system for NO REGRESSH"""
    
    def __init__(self):
        self.framework = NoRegreshFramework()
        self.scanner = NetworkScanner(self.framework)
        self.exploit_manager = ExploitManager(self.framework)
        self.listener_manager = ListenerManager(self.framework)
        self.system_checker = SystemChecker(self.framework)
        
    def show_main_menu(self):
        """Show main menu"""
        print(f"{Colors.BOLD}╔═══════════════════ Main Menu ═══════════════════╗{Colors.RESET}")
        print("║                                                 ║")
        print(f"║  1) {Colors.CYAN}🔍 Network Scanner{Colors.RESET}                        ║")
        print("║     (SSH Services & Vulnerability Scan)        ║")
        print("║                                                 ║")
        print(f"║  2) {Colors.RED}💥 Targeted Exploitation{Colors.RESET}                  ║")
        print("║     (CVE-2024-6387 & Other SSH Exploits)       ║")
        print("║                                                 ║")
        print(f"║  3) {Colors.GREEN}📊 Listener Management{Colors.RESET}                    ║")
        print("║     (Python, Netcat & Socat Listeners)        ║")
        print("║                                                 ║")
        print(f"║  4) {Colors.YELLOW}⚙️  System Status{Colors.RESET}                         ║")
        print("║     (System Check & Configuration)             ║")
        print("║                                                 ║")
        print(f"║  5) {Colors.MAGENTA}📁 Log Viewer{Colors.RESET}                             ║")
        print("║     (Session Logs & Reports)                  ║")
        print("║                                                 ║")
        print(f"║  6) {Colors.WHITE}❌ Exit{Colors.RESET}                                  ║")
        print("║                                                 ║")
        print("╚═════════════════════════════════════════════════╝")
        print(f"\n{Colors.BOLD}Selection: {Colors.RESET}", end="")
        
    def show_scanner_menu(self):
        """Scanner submenu"""
        print(f"\n{Colors.BOLD}╔═══════════════ Scanner Options ═══════════════╗{Colors.RESET}")
        print("║                                                 ║")
        print("║  1) IP Range Scan                              ║")
        print("║  2) Single Target Scan                         ║")
        print("║  3) Quick Scan (Local Network)                 ║")
        print("║  4) Custom CVE Selection                      ║")
        print("║  5) Return to Main Menu                       ║")
        print("║                                                 ║")
        print("╚═════════════════════════════════════════════════╝")
        print(f"{Colors.BOLD}Selection: {Colors.RESET}", end="")
        
        try:
            choice = int(input())
        except ValueError:
            self.framework.print_status(StatusLevel.ERROR, "Invalid input")
            return
            
        if choice == 1:
            self.scanner.interactive_scan()
        elif choice == 2:
            self._single_target_scan()
        elif choice == 3:
            self._quick_scan()
        elif choice == 4:
            self._custom_cve_scan()
        elif choice == 5:
            return
        else:
            self.framework.print_status(StatusLevel.ERROR, "Invalid selection")
            
    def _single_target_scan(self):
        """Scan single target"""
        print(f"\n{Colors.BOLD}╔═══════════════ Single Target Scan ═══════════════╗{Colors.RESET}")
        
        target_ip = input("Enter target IP: ").strip()
        if not self.framework.validate_ip(target_ip):
            self.framework.print_status(StatusLevel.ERROR, "Invalid IP address")
            return
            
        try:
            port = int(input("Port (default: 22): ") or "22")
        except ValueError:
            port = 22
            
        # CVE selection
        print("\nCVE Selection:")
        print("1) All CVEs")
        print("2) CVE-2024-6387 only")
        print("3) Username enumeration CVEs only")
        
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
        else:
            scan_cves = ["CVE-2024-6387", "CVE-2020-14145", "CVE-2021-28041", "CVE-2019-16905", "CVE-2018-15473"]
            
        result = self.scanner.scan_single_target(target_ip, port, scan_cves)
        
        if result:
            self.scanner.display_results([result])
            
            # Export option
            export = input("\nExport result? (y/n): ").lower().strip()
            if export in ['y', 'yes']:
                self.scanner.export_results([result])
        else:
            self.framework.print_status(StatusLevel.WARN, "No SSH service found")
            
    def _quick_scan(self):
        """Quick scan of local network"""
        print(f"\n{Colors.BOLD}╔═══════════════ Quick Scan ═══════════════╗{Colors.RESET}")
        print("Scanning local network (192.168.1.1-254)...")
        
        # Automatic IP range for local network
        results = self.scanner.scan_ip_range("192.168.1.1", "192.168.1.254", 
                                           port=22, max_threads=30)
        
        if results:
            self.scanner.display_results(results)
            
            # Automatic export
            self.scanner.export_results(results, "quick_scan_results.csv")
        else:
            self.framework.print_status(StatusLevel.WARN, 
                "No SSH services found in local network")
                
    def _custom_cve_scan(self):
        """Custom CVE selection scan"""
        print(f"\n{Colors.BOLD}╔═══════════════ Custom CVE Scan ═══════════════╗{Colors.RESET}")
        
        print("Available CVEs:")
        print("1) CVE-2024-6387 (regreSSHion) - Remote Code Execution")
        print("2) CVE-2020-14145 - Username Enumeration")
        print("3) CVE-2021-28041 - Username Enumeration")
        print("4) CVE-2019-16905 - Username Enumeration")
        print("5) CVE-2018-15473 - Username Enumeration")
        
        cve_input = input("Enter CVE numbers (comma-separated, e.g., 1,2,3): ").strip()
        cve_map = {
            "1": "CVE-2024-6387",
            "2": "CVE-2020-14145",
            "3": "CVE-2021-28041",
            "4": "CVE-2019-16905",
            "5": "CVE-2018-15473"
        }
        
        scan_cves = []
        for cve_num in cve_input.split(','):
            cve_num = cve_num.strip()
            if cve_num in cve_map:
                scan_cves.append(cve_map[cve_num])
                
        if not scan_cves:
            self.framework.print_status(StatusLevel.ERROR, "No valid CVEs selected")
            return
            
        # IP range input
        start_ip = input("Enter start IP (e.g., 192.168.1.1): ").strip()
        if not self.framework.validate_ip(start_ip):
            self.framework.print_status(StatusLevel.ERROR, "Invalid start IP")
            return
            
        end_ip = input("Enter end IP (e.g., 192.168.1.254): ").strip()
        if not self.framework.validate_ip(end_ip):
            self.framework.print_status(StatusLevel.ERROR, "Invalid end IP")
            return
            
        # Execute scan
        results = self.scanner.scan_ip_range(start_ip, end_ip, port=22, 
                                           max_threads=20, scan_cves=scan_cves)
        
        if results:
            self.scanner.display_results(results)
            
            # Export option
            export = input("\nExport results? (y/n): ").lower().strip()
            if export in ['y', 'yes']:
                self.scanner.export_results(results)
                
    def show_listener_menu(self):
        """Listener management menu"""
        print(f"\n{Colors.BOLD}╔═══════════════ Listener Management ═══════════════╗{Colors.RESET}")
        
        # Show active listeners
        self.listener_manager.list_active_listeners()
        
        print("║                                                 ║")
        print("║  1) Start Python Listener                       ║")
        print("║  2) Start Netcat Listener                       ║")
        print("║  3) Start Socat Listener                        ║")
        print("║  4) Stop Listener                               ║")
        print("║  5) Stop All Listeners                          ║")
        print("║  6) Return to Main Menu                         ║")
        print("║                                                 ║")
        print("╚═════════════════════════════════════════════════╝")
        print(f"{Colors.BOLD}Selection: {Colors.RESET}", end="")
        
        try:
            choice = int(input())
        except ValueError:
            self.framework.print_status(StatusLevel.ERROR, "Invalid input")
            return
            
        if choice == 1:
            self._start_python_listener()
        elif choice == 2:
            self._start_netcat_listener()
        elif choice == 3:
            self._start_socat_listener()
        elif choice == 4:
            self._stop_listener()
        elif choice == 5:
            self.listener_manager.stop_all_listeners()
        elif choice == 6:
            return
        else:
            self.framework.print_status(StatusLevel.ERROR, "Invalid selection")
            
    def _start_python_listener(self):
        """Start Python listener"""
        try:
            port = int(input("Enter port (default: 4444): ") or "4444")
            if not self.framework.validate_port(port):
                self.framework.print_status(StatusLevel.ERROR, "Invalid port")
                return
                
            interactive = input("Enable interactive shell? (y/n, default: y): ").lower().strip()
            interactive = interactive in ['', 'y', 'yes']
            
            success = self.listener_manager.start_listener(port, "python", interactive)
            
            if success:
                self.framework.print_status(StatusLevel.SUCCESS, 
                    f"Python listener started on port {port}")
                if interactive:
                    self.framework.print_status(StatusLevel.INFO, 
                        "Interactive shell enabled - waiting for connections...")
            else:
                self.framework.print_status(StatusLevel.ERROR, 
                    "Error starting Python listener")
                    
        except ValueError:
            self.framework.print_status(StatusLevel.ERROR, "Invalid port input")
            
    def _start_netcat_listener(self):
        """Start Netcat listener"""
        try:
            port = int(input("Enter port (default: 4444): ") or "4444")
            if not self.framework.validate_port(port):
                self.framework.print_status(StatusLevel.ERROR, "Invalid port")
                return
                
            interactive = input("Enable interactive shell? (y/n, default: y): ").lower().strip()
            interactive = interactive in ['', 'y', 'yes']
            
            success = self.listener_manager.start_listener(port, "netcat", interactive)
            
            if success:
                self.framework.print_status(StatusLevel.SUCCESS, 
                    f"Netcat listener started on port {port}")
            else:
                self.framework.print_status(StatusLevel.ERROR, 
                    "Error starting Netcat listener")
                    
        except ValueError:
            self.framework.print_status(StatusLevel.ERROR, "Invalid port input")
            
    def _start_socat_listener(self):
        """Start Socat listener"""
        try:
            port = int(input("Enter port (default: 4444): ") or "4444")
            if not self.framework.validate_port(port):
                self.framework.print_status(StatusLevel.ERROR, "Invalid port")
                return
                
            interactive = input("Enable interactive shell? (y/n, default: y): ").lower().strip()
            interactive = interactive in ['', 'y', 'yes']
            
            success = self.listener_manager.start_listener(port, "socat", interactive)
            
            if success:
                self.framework.print_status(StatusLevel.SUCCESS, 
                    f"Socat listener started on port {port}")
            else:
                self.framework.print_status(StatusLevel.ERROR, 
                    "Error starting Socat listener")
                    
        except ValueError:
            self.framework.print_status(StatusLevel.ERROR, "Invalid port input")
            
    def _stop_listener(self):
        """Stop specific listener"""
        try:
            port = int(input("Port of listener to stop: "))
            self.listener_manager.stop_listener(port)
        except ValueError:
            self.framework.print_status(StatusLevel.ERROR, "Invalid port input")
            
    def show_system_menu(self):
        """System status menu"""
        print(f"\n{Colors.BOLD}╔═══════════════ System Management ═══════════════╗{Colors.RESET}")
        print("║                                                 ║")
        print("║  1) Display Complete System Status              ║")
        print("║  2) Check System Requirements                   ║")
        print("║  3) Validate IP Configuration                   ║")
        print("║  4) Install Missing Dependencies                ║")
        print("║  5) Create System Report                        ║")
        print("║  6) Return to Main Menu                         ║")
        print("║                                                 ║")
        print("╚═════════════════════════════════════════════════╝")
        print(f"{Colors.BOLD}Selection: {Colors.RESET}", end="")
        
        try:
            choice = int(input())
        except ValueError:
            self.framework.print_status(StatusLevel.ERROR, "Invalid input")
            return
            
        if choice == 1:
            self.system_checker.display_system_status()
        elif choice == 2:
            self._check_requirements()
        elif choice == 3:
            self._validate_ip_config()
        elif choice == 4:
            self.system_checker.install_missing_dependencies()
        elif choice == 5:
            self._create_system_report()
        elif choice == 6:
            return
        else:
            self.framework.print_status(StatusLevel.ERROR, "Invalid selection")
            
    def _check_requirements(self):
        """Check system requirements"""
        print(f"\n{Colors.BOLD}Checking System Requirements...{Colors.RESET}")
        requirements = self.system_checker.check_system_requirements()
        
        print(f"\n{Colors.BOLD}Results:{Colors.RESET}")
        for requirement, status in requirements.items():
            status_color = Colors.GREEN if status else Colors.RED
            status_text = "✓" if status else "✗"
            print(f"  {status_color}{status_text}{Colors.RESET} {requirement.replace('_', ' ').title()}")
            
    def _validate_ip_config(self):
        """Validate IP configuration"""
        print(f"\n{Colors.BOLD}IP Configuration Validation{Colors.RESET}")
        
        ip = input("Enter IP address: ").strip()
        if not self.framework.validate_ip(ip):
            self.framework.print_status(StatusLevel.ERROR, "Invalid IP address")
            return
            
        try:
            port = int(input("Port (default: 22): ") or "22")
        except ValueError:
            port = 22
            
        validation_results = self.system_checker.validate_ip_configuration(ip, port)
        
        print(f"\n{Colors.BOLD}Validation Results:{Colors.RESET}")
        for check, status in validation_results.items():
            status_color = Colors.GREEN if status else Colors.RED
            status_text = "✓" if status else "✗"
            print(f"  {status_color}{status_text}{Colors.RESET} {check.replace('_', ' ').title()}")
            
    def _create_system_report(self):
        """Create system report"""
        filename = input("Filename (Enter for automatic): ").strip()
        if not filename:
            filename = None
            
        report_file = self.system_checker.create_system_report(filename)
        
        if report_file:
            print(f"\n{Colors.BOLD}System Report Created:{Colors.RESET}")
            print(f"  File: {report_file}")
            print(f"  Format: JSON")
            print(f"  Content: System Info, Requirements, Tools")
            
    def show_log_menu(self):
        """Log viewer menu"""
        print(f"\n{Colors.BOLD}╔═══════════════ Log Viewer ═══════════════╗{Colors.RESET}")
        print("║                                             ║")
        print("║  1) Display Current Session Logs            ║")
        print("║  2) Search Logs                              ║")
        print("║  3) List Log Files                           ║")
        print("║  4) Clear Logs                               ║")
        print("║  5) Return to Main Menu                      ║")
        print("║                                             ║")
        print("╚═════════════════════════════════════════════╝")
        print(f"{Colors.BOLD}Selection: {Colors.RESET}", end="")
        
        try:
            choice = int(input())
        except ValueError:
            self.framework.print_status(StatusLevel.ERROR, "Invalid input")
            return
            
        if choice == 1:
            self._show_current_logs()
        elif choice == 2:
            self._search_logs()
        elif choice == 3:
            self._list_log_files()
        elif choice == 4:
            self._clear_logs()
        elif choice == 5:
            return
        else:
            self.framework.print_status(StatusLevel.ERROR, "Invalid selection")
            
    def _show_current_logs(self):
        """Show current logs"""
        if self.framework.log_file and self.framework.log_file.exists():
            print(f"\n{Colors.BOLD}Current Session Logs:{Colors.RESET}")
            print("─" * 60)
            
            try:
                with open(self.framework.log_file, 'r', encoding='utf-8') as f:
                    lines = f.readlines()
                    # Show last 50 lines
                    for line in lines[-50:]:
                        print(line.rstrip())
            except Exception as e:
                self.framework.print_status(StatusLevel.ERROR, 
                    f"Error reading logs: {e}")
        else:
            self.framework.print_status(StatusLevel.WARN, "No log file found")
            
    def _search_logs(self):
        """Search logs"""
        search_term = input("Enter search term: ").strip()
        if not search_term:
            return
            
        if self.framework.log_file and self.framework.log_file.exists():
            try:
                with open(self.framework.log_file, 'r', encoding='utf-8') as f:
                    lines = f.readlines()
                    
                matching_lines = [line for line in lines if search_term.lower() in line.lower()]
                
                if matching_lines:
                    print(f"\n{Colors.BOLD}Found entries for '{search_term}':{Colors.RESET}")
                    print("─" * 60)
                    for line in matching_lines:
                        print(line.rstrip())
                else:
                    self.framework.print_status(StatusLevel.INFO, 
                        f"No entries found for '{search_term}'")
                        
            except Exception as e:
                self.framework.print_status(StatusLevel.ERROR, 
                    f"Error searching logs: {e}")
        else:
            self.framework.print_status(StatusLevel.WARN, "No log file found")
            
    def _list_log_files(self):
        """List all log files"""
        logs_dir = self.framework.log_file.parent if self.framework.log_file else None
        
        if logs_dir and logs_dir.exists():
            log_files = list(logs_dir.glob("*.log"))
            
            if log_files:
                print(f"\n{Colors.BOLD}Available Log Files:{Colors.RESET}")
                for log_file in sorted(log_files):
                    size = log_file.stat().st_size
                    print(f"  {log_file.name} ({size} bytes)")
            else:
                self.framework.print_status(StatusLevel.INFO, "No log files found")
        else:
            self.framework.print_status(StatusLevel.WARN, "Log directory not found")
            
    def _clear_logs(self):
        """Clear logs"""
        confirm = input("Clear all logs? (y/N): ").lower().strip()
        if confirm in ['y', 'yes']:
            logs_dir = self.framework.log_file.parent if self.framework.log_file else None
            
            if logs_dir and logs_dir.exists():
                log_files = list(logs_dir.glob("*.log"))
                for log_file in log_files:
                    log_file.unlink()
                    
                self.framework.print_status(StatusLevel.SUCCESS, 
                    f"{len(log_files)} log files cleared")
            else:
                self.framework.print_status(StatusLevel.WARN, "No logs to clear")
        else:
            self.framework.print_status(StatusLevel.INFO, "Clear operation cancelled")
            
    def run(self):
        """Main menu system loop"""
        self.framework.print_banner()
        self.framework.print_status(StatusLevel.SUCCESS, 
            "NO REGRESSH Framework started")
        
        while True:
            try:
                self.show_main_menu()
                
                choice = input().strip()
                
                if choice == "1":
                    self.show_scanner_menu()
                elif choice == "2":
                    self.exploit_manager.interactive_exploit()
                elif choice == "3":
                    self.show_listener_menu()
                elif choice == "4":
                    self.show_system_menu()
                elif choice == "5":
                    self.show_log_menu()
                elif choice == "6":
                    self.framework.print_status(StatusLevel.INFO, 
                        "Framework shutting down...")
                    self.framework.cleanup()
                    break
                else:
                    self.framework.print_status(StatusLevel.ERROR, 
                        "Invalid selection")
                    
                # Pause between menus
                if choice in ["1", "2", "3", "4", "5"]:
                    input(f"\n{Colors.YELLOW}Press Enter to continue...{Colors.RESET}")
                    self.framework.print_banner()
                    
            except KeyboardInterrupt:
                self.framework.print_status(StatusLevel.WARN, 
                    "Interrupted by user")
                self.framework.cleanup()
                break
            except Exception as e:
                self.framework.print_status(StatusLevel.ERROR, 
                    f"Unexpected error: {e}")
                input(f"\n{Colors.YELLOW}Press Enter to continue...{Colors.RESET}")

if __name__ == "__main__":
    menu = MenuSystem()
    menu.run()
