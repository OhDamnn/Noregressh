#!/usr/bin/env python3
"""
NO REGRESSH - Enhanced CVE-2024-6387 Exploit Framework
Complete Python framework with advanced features for authorized penetration testing
"""

import os
import sys
import time
import socket
import threading
import subprocess
import ipaddress
import json
import csv
import signal
import logging
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Optional, Tuple
import argparse
import requests
from pathlib import Path

# Terminal output colors
class Colors:
    RESET = '\033[0m'
    RED = '\033[31m'
    GREEN = '\033[32m'
    YELLOW = '\033[33m'
    BLUE = '\033[34m'
    MAGENTA = '\033[35m'
    CYAN = '\033[36m'
    WHITE = '\033[37m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

class StatusLevel:
    INFO = "INFO"
    WARN = "WARN"
    ERROR = "ERROR"
    SUCCESS = "SUCCESS"
    VULN = "VULN"
    DEBUG = "DEBUG"
    CRITICAL = "CRITICAL"

class NoRegreshFramework:
    def __init__(self):
        self.listener_process = None
        self.listener_port = 4444
        self.attacker_ip = ""
        self.scan_results = []
        self.vulnerable_count = 0
        self.log_file = None
        self.setup_logging()
        self.setup_signal_handlers()
        
    def setup_logging(self):
        """Setup detailed logging system"""
        log_dir = Path("logs")
        log_dir.mkdir(exist_ok=True)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        log_file = log_dir / f"no_regresh_{timestamp}.log"
        
        # Create formatter
        formatter = logging.Formatter(
            '%(asctime)s [%(levelname)s] %(name)s: %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        
        # File handler
        file_handler = logging.FileHandler(log_file, encoding='utf-8')
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(formatter)
        
        # Console handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        console_handler.setFormatter(formatter)
        
        # Setup logger
        self.logger = logging.getLogger('NO_REGRESSH')
        self.logger.setLevel(logging.DEBUG)
        self.logger.addHandler(file_handler)
        self.logger.addHandler(console_handler)
        
        self.log_file = log_file
        
    def setup_signal_handlers(self):
        """Setup signal handlers for clean shutdown"""
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)
        
    def signal_handler(self, signum, frame):
        """Signal handler for clean shutdown"""
        self.print_status(StatusLevel.WARN, f"Signal {signum} received. Cleaning up resources...")
        self.cleanup()
        sys.exit(0)
        
    def cleanup(self):
        """Clean up all resources"""
        if self.listener_process:
            self.print_status(StatusLevel.INFO, "Stopping listener process...")
            self.listener_process.terminate()
            try:
                self.listener_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.listener_process.kill()
            self.listener_process = None
            
    def print_banner(self):
        """Display the NO REGRESSH banner"""
        os.system('clear' if os.name == 'posix' else 'cls')
        
        banner = f"""
{Colors.CYAN}╔══════════════════════════════════════════════════════════════════╗
║                                                                  ║
║    {Colors.BOLD}{Colors.WHITE}NO REGRESSH - Enhanced Framework{Colors.RESET}{Colors.CYAN}                        ║
║    {Colors.YELLOW}CVE-2024-6387 Scanner & Exploit Tool{Colors.RESET}{Colors.CYAN}                     ║
║                                                                  ║
║    {Colors.RED}⚠️  For authorized penetration testing only! ⚠️{Colors.RESET}{Colors.CYAN}          ║
║                                                                  ║
║    {Colors.GREEN}Version 3.0 - Advanced Python Framework{Colors.RESET}{Colors.CYAN}                ║
║                                                                  ║
╚══════════════════════════════════════════════════════════════════╝{Colors.RESET}
"""
        print(banner)
        
    def print_status(self, level: str, message: str, verbose: bool = True):
        """Enhanced status output with detailed information"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        
        color_map = {
            StatusLevel.INFO: Colors.GREEN,
            StatusLevel.WARN: Colors.YELLOW,
            StatusLevel.ERROR: Colors.RED,
            StatusLevel.SUCCESS: Colors.BOLD + Colors.GREEN,
            StatusLevel.VULN: Colors.BOLD + Colors.RED,
            StatusLevel.DEBUG: Colors.MAGENTA,
            StatusLevel.CRITICAL: Colors.BOLD + Colors.RED
        }
        
        color = color_map.get(level, Colors.WHITE)
        
        if verbose:
            print(f"{Colors.BLUE}[{timestamp}]{Colors.RESET} [{color}{level}{Colors.RESET}] {message}")
        
        # Logging
        log_level = getattr(logging, level, logging.INFO)
        self.logger.log(log_level, f"[{level}] {message}")
        
    def print_progress_bar(self, current: int, total: int, prefix: str = "Progress"):
        """Enhanced progress display"""
        bar_width = 50
        progress = current / total
        pos = int(bar_width * progress)
        
        bar = "=" * pos + ">" + " " * (bar_width - pos - 1)
        percentage = progress * 100
        
        print(f"\r{prefix} [{bar}] {current}/{total} ({percentage:.1f}%)", end="", flush=True)
        
    def get_public_ip(self) -> Optional[str]:
        """Determine public IP with multiple fallback options"""
        services = [
            "https://api.ipify.org",
            "https://ifconfig.me/ip",
            "https://ipecho.net/plain",
            "https://icanhazip.com",
            "https://ident.me"
        ]
        
        for service in services:
            try:
                self.print_status(StatusLevel.DEBUG, f"Trying IP service: {service}")
                response = requests.get(service, timeout=5)
                if response.status_code == 200:
                    ip = response.text.strip()
                    if self.validate_ip(ip):
                        self.print_status(StatusLevel.SUCCESS, f"Public IP determined: {ip}")
                        return ip
            except Exception as e:
                self.print_status(StatusLevel.DEBUG, f"Service {service} failed: {e}")
                continue
                
        self.print_status(StatusLevel.WARN, "No public IP determined")
        return None
        
    def validate_ip(self, ip: str) -> bool:
        """Validate IP address"""
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False
            
    def validate_port(self, port: int) -> bool:
        """Validate port number"""
        return 1 <= port <= 65535
        
    def check_ip_reachability(self, ip: str, port: int = 22, timeout: int = 3) -> bool:
        """Check if IP is reachable"""
        try:
            self.print_status(StatusLevel.DEBUG, f"Checking reachability of {ip}:{port}")
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            sock.close()
            
            if result == 0:
                self.print_status(StatusLevel.SUCCESS, f"{ip}:{port} is reachable")
                return True
            else:
                self.print_status(StatusLevel.WARN, f"{ip}:{port} is not reachable")
                return False
        except Exception as e:
            self.print_status(StatusLevel.ERROR, f"Error during reachability test: {e}")
            return False
            
    def grab_ssh_banner(self, ip: str, port: int = 22) -> Tuple[bool, str, float]:
        """Grab SSH banner with timing information"""
        start_time = time.time()
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            
            self.print_status(StatusLevel.DEBUG, f"Connecting to {ip}:{port}")
            sock.connect((ip, port))
            
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            sock.close()
            
            response_time = (time.time() - start_time) * 1000
            
            if banner:
                self.print_status(StatusLevel.INFO, f"Banner received from {ip}:{port} - {banner[:50]}...")
                return True, banner, response_time
            else:
                self.print_status(StatusLevel.WARN, f"Empty banner from {ip}:{port}")
                return False, "", response_time
                
        except Exception as e:
            response_time = (time.time() - start_time) * 1000
            self.print_status(StatusLevel.DEBUG, f"Banner grab failed for {ip}:{port}: {e}")
            return False, "", response_time
            
    def check_ssh_vulnerability(self, banner: str) -> Dict[str, bool]:
        """Check SSH banner for known vulnerabilities"""
        vulnerabilities = {
            'CVE-2024-6387': False,
            'CVE-2021-28041': False,
            'CVE-2020-14145': False,
            'CVE-2019-16905': False,
            'CVE-2018-15473': False
        }
        
        if not banner or len(banner) < 10:
            return vulnerabilities
            
        # CVE-2024-6387 (regreSSHion)
        vulnerable_versions_6387 = [
            "OpenSSH_8.5", "OpenSSH_8.6", "OpenSSH_8.7", "OpenSSH_8.8",
            "OpenSSH_8.9", "OpenSSH_9.0", "OpenSSH_9.1", "OpenSSH_9.2",
            "OpenSSH_9.3", "OpenSSH_9.4", "OpenSSH_9.5", "OpenSSH_9.6",
            "OpenSSH_9.7"
        ]
        
        for version in vulnerable_versions_6387:
            if version in banner:
                vulnerabilities['CVE-2024-6387'] = True
                self.print_status(StatusLevel.VULN, f"CVE-2024-6387 vulnerable version detected: {version}")
                break
                
        # CVE-2021-28041 (Username enumeration)
        if "OpenSSH_8.2" in banner or "OpenSSH_8.3" in banner:
            vulnerabilities['CVE-2021-28041'] = True
            self.print_status(StatusLevel.VULN, "CVE-2021-28041 potentially vulnerable")
            
        # CVE-2020-14145 (Username enumeration)
        if "OpenSSH_7.4" in banner or "OpenSSH_7.5" in banner:
            vulnerabilities['CVE-2020-14145'] = True
            self.print_status(StatusLevel.VULN, "CVE-2020-14145 potentially vulnerable")
            
        # CVE-2019-16905 (Username enumeration)
        if "OpenSSH_7.9" in banner or "OpenSSH_8.0" in banner:
            vulnerabilities['CVE-2019-16905'] = True
            self.print_status(StatusLevel.VULN, "CVE-2019-16905 potentially vulnerable")
            
        # CVE-2018-15473 (Username enumeration)
        if "OpenSSH_7.7" in banner or "OpenSSH_7.8" in banner:
            vulnerabilities['CVE-2018-15473'] = True
            self.print_status(StatusLevel.VULN, "CVE-2018-15473 potentially vulnerable")
                
        if not any(vulnerabilities.values()):
            self.print_status(StatusLevel.INFO, "No known vulnerable versions detected")
            
        return vulnerabilities

if __name__ == "__main__":
    framework = NoRegreshFramework()
    framework.print_banner()
    framework.print_status(StatusLevel.SUCCESS, "NO REGRESSH Framework started")
