#!/usr/bin/env python3
"""
NO REGRESSH - System Check & Management Module
Advanced system verification and management functions
"""

import os
import sys
import platform
import subprocess
import socket
import psutil
import requests
from typing import Dict, List, Tuple, Optional
from pathlib import Path
import json
from datetime import datetime

from no_regresh_main import NoRegreshFramework, StatusLevel, Colors

class SystemChecker:
    """System verification and management"""
    
    def __init__(self, framework: NoRegreshFramework):
        self.framework = framework
        
    def check_system_requirements(self) -> Dict[str, bool]:
        """Check all system requirements"""
        self.framework.print_status(StatusLevel.INFO, "Starting system verification...")
        
        requirements = {
            'python_version': self._check_python_version(),
            'required_modules': self._check_required_modules(),
            'network_tools': self._check_network_tools(),
            'permissions': self._check_permissions(),
            'disk_space': self._check_disk_space(),
            'memory': self._check_memory(),
            'network_connectivity': self._check_network_connectivity(),
            'firewall_status': self._check_firewall_status(),
            'antivirus_status': self._check_antivirus_status()
        }
        
        # Summary
        passed = sum(requirements.values())
        total = len(requirements)
        
        self.framework.print_status(StatusLevel.INFO, 
            f"System verification completed: {passed}/{total} tests passed")
            
        return requirements
        
    def _check_python_version(self) -> bool:
        """Check Python version"""
        version = sys.version_info
        required_version = (3, 7)
        
        if version >= required_version:
            self.framework.print_status(StatusLevel.SUCCESS, 
                f"Python version OK: {version.major}.{version.minor}.{version.micro}")
            return True
        else:
            self.framework.print_status(StatusLevel.ERROR, 
                f"Python version too old: {version.major}.{version.minor}.{version.micro} "
                f"(Minimum {required_version[0]}.{required_version[1]} required)")
            return False
            
    def _check_required_modules(self) -> bool:
        """Check required Python modules"""
        required_modules = [
            'socket', 'threading', 'subprocess', 'requests', 
            'psutil', 'pathlib', 'json', 'datetime', 'csv',
            'concurrent.futures', 'ipaddress', 'base64'
        ]
        
        missing_modules = []
        
        for module in required_modules:
            try:
                __import__(module)
                self.framework.print_status(StatusLevel.DEBUG, 
                    f"Module {module} available")
            except ImportError:
                missing_modules.append(module)
                self.framework.print_status(StatusLevel.ERROR, 
                    f"Module {module} missing")
                
        if missing_modules:
            self.framework.print_status(StatusLevel.ERROR, 
                f"Missing modules: {', '.join(missing_modules)}")
            return False
        else:
            self.framework.print_status(StatusLevel.SUCCESS, 
                "All required modules available")
            return True
            
    def _check_network_tools(self) -> bool:
        """Check available network tools"""
        tools = {
            'curl': 'curl --version',
            'wget': 'wget --version',
            'nc': 'nc --version',
            'ncat': 'ncat --version',
            'netcat': 'netcat --version',
            'socat': 'socat --version',
            'nmap': 'nmap --version',
            'ping': 'ping -V'
        }
        
        available_tools = []
        
        for tool, cmd in tools.items():
            try:
                result = subprocess.run(cmd.split(), capture_output=True, 
                                      text=True, timeout=5)
                if result.returncode == 0:
                    available_tools.append(tool)
                    self.framework.print_status(StatusLevel.SUCCESS, 
                        f"Tool {tool} available")
                else:
                    self.framework.print_status(StatusLevel.DEBUG, 
                        f"Tool {tool} not available")
            except (subprocess.TimeoutExpired, FileNotFoundError):
                self.framework.print_status(StatusLevel.DEBUG, 
                    f"Tool {tool} not found")
                
        if available_tools:
            self.framework.print_status(StatusLevel.SUCCESS, 
                f"Available tools: {', '.join(available_tools)}")
            return True
        else:
            self.framework.print_status(StatusLevel.WARN, 
                "No network tools found")
            return False
            
    def _check_permissions(self) -> bool:
        """Check system permissions"""
        try:
            # Test socket permission
            test_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            test_socket.close()
            
            # Test file write permission
            test_file = Path("test_permissions.tmp")
            test_file.write_text("test")
            test_file.unlink()
            
            # Test port binding (privileged ports)
            try:
                test_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                test_socket.bind(('127.0.0.1', 0))  # Bind to any available port
                test_socket.close()
            except Exception:
                self.framework.print_status(StatusLevel.WARN, 
                    "Cannot bind to ports (may need root privileges)")
            
            self.framework.print_status(StatusLevel.SUCCESS, 
                "System permissions OK")
            return True
            
        except Exception as e:
            self.framework.print_status(StatusLevel.ERROR, 
                f"Permission issue: {e}")
            return False
            
    def _check_disk_space(self) -> bool:
        """Check available disk space"""
        try:
            disk_usage = psutil.disk_usage('/')
            free_gb = disk_usage.free / (1024**3)
            
            if free_gb > 1.0:  # At least 1 GB free
                self.framework.print_status(StatusLevel.SUCCESS, 
                    f"Disk space OK: {free_gb:.1f} GB free")
                return True
            else:
                self.framework.print_status(StatusLevel.WARN, 
                    f"Low disk space: {free_gb:.1f} GB free")
                return False
                
        except Exception as e:
            self.framework.print_status(StatusLevel.ERROR, 
                f"Error checking disk space: {e}")
            return False
            
    def _check_memory(self) -> bool:
        """Check available memory"""
        try:
            memory = psutil.virtual_memory()
            available_gb = memory.available / (1024**3)
            
            if available_gb > 0.5:  # At least 512 MB available
                self.framework.print_status(StatusLevel.SUCCESS, 
                    f"Memory OK: {available_gb:.1f} GB available")
                return True
            else:
                self.framework.print_status(StatusLevel.WARN, 
                    f"Low memory: {available_gb:.1f} GB available")
                return False
                
        except Exception as e:
            self.framework.print_status(StatusLevel.ERROR, 
                f"Error checking memory: {e}")
            return False
            
    def _check_network_connectivity(self) -> bool:
        """Check network connectivity"""
        test_urls = [
            "https://www.google.com",
            "https://www.github.com",
            "https://api.ipify.org",
            "https://httpbin.org/ip"
        ]
        
        successful_connections = 0
        
        for url in test_urls:
            try:
                response = requests.get(url, timeout=5)
                if response.status_code == 200:
                    successful_connections += 1
                    self.framework.print_status(StatusLevel.DEBUG, 
                        f"Connection to {url} successful")
                else:
                    self.framework.print_status(StatusLevel.DEBUG, 
                        f"Connection to {url} failed: {response.status_code}")
            except Exception as e:
                self.framework.print_status(StatusLevel.DEBUG, 
                    f"Connection to {url} failed: {e}")
                
        if successful_connections > 0:
            self.framework.print_status(StatusLevel.SUCCESS, 
                f"Network connectivity OK: {successful_connections}/{len(test_urls)} connections successful")
            return True
        else:
            self.framework.print_status(StatusLevel.ERROR, 
                "No network connectivity")
            return False
            
    def _check_firewall_status(self) -> bool:
        """Check firewall status"""
        try:
            system = platform.system().lower()
            
            if system == "linux":
                # Check iptables
                try:
                    result = subprocess.run(['iptables', '-L'], 
                                          capture_output=True, text=True, timeout=5)
                    if result.returncode == 0:
                        self.framework.print_status(StatusLevel.INFO, 
                            "iptables firewall detected")
                        return True
                except (subprocess.TimeoutExpired, FileNotFoundError):
                    pass
                    
                # Check UFW
                try:
                    result = subprocess.run(['ufw', 'status'], 
                                          capture_output=True, text=True, timeout=5)
                    if result.returncode == 0:
                        self.framework.print_status(StatusLevel.INFO, 
                            "UFW firewall detected")
                        return True
                except (subprocess.TimeoutExpired, FileNotFoundError):
                    pass
                    
            elif system == "darwin":  # macOS
                try:
                    result = subprocess.run(['pfctl', '-s', 'info'], 
                                          capture_output=True, text=True, timeout=5)
                    if result.returncode == 0:
                        self.framework.print_status(StatusLevel.INFO, 
                            "pfctl firewall detected")
                        return True
                except (subprocess.TimeoutExpired, FileNotFoundError):
                    pass
                    
            elif system == "windows":
                try:
                    result = subprocess.run(['netsh', 'advfirewall', 'show', 'allprofiles'], 
                                          capture_output=True, text=True, timeout=5)
                    if result.returncode == 0:
                        self.framework.print_status(StatusLevel.INFO, 
                            "Windows Firewall detected")
                        return True
                except (subprocess.TimeoutExpired, FileNotFoundError):
                    pass
                    
            self.framework.print_status(StatusLevel.INFO, 
                "No firewall detected or accessible")
            return True  # Not necessarily a problem
            
        except Exception as e:
            self.framework.print_status(StatusLevel.DEBUG, 
                f"Error checking firewall: {e}")
            return True
            
    def _check_antivirus_status(self) -> bool:
        """Check antivirus status"""
        try:
            system = platform.system().lower()
            
            if system == "linux":
                # Check common Linux antivirus tools
                av_tools = ['clamav', 'sophos', 'kaspersky']
                for tool in av_tools:
                    try:
                        result = subprocess.run([tool, '--version'], 
                                              capture_output=True, timeout=3)
                        if result.returncode == 0:
                            self.framework.print_status(StatusLevel.INFO, 
                                f"Antivirus detected: {tool}")
                            return True
                    except (subprocess.TimeoutExpired, FileNotFoundError):
                        continue
                        
            elif system == "windows":
                # Check Windows Defender
                try:
                    result = subprocess.run(['powershell', '-Command', 
                                          'Get-MpComputerStatus'], 
                                          capture_output=True, timeout=5)
                    if result.returncode == 0:
                        self.framework.print_status(StatusLevel.INFO, 
                            "Windows Defender detected")
                        return True
                except (subprocess.TimeoutExpired, FileNotFoundError):
                    pass
                    
            self.framework.print_status(StatusLevel.INFO, 
                "No antivirus detected")
            return True  # Not necessarily a problem
            
        except Exception as e:
            self.framework.print_status(StatusLevel.DEBUG, 
                f"Error checking antivirus: {e}")
            return True
            
    def validate_ip_configuration(self, ip: str, port: int = 22) -> Dict[str, bool]:
        """Validate IP configuration and reachability"""
        self.framework.print_status(StatusLevel.INFO, 
            f"Validating IP configuration for {ip}:{port}")
            
        validation_results = {
            'ip_format_valid': False,
            'ip_reachable': False,
            'port_open': False,
            'ssh_service': False,
            'firewall_blocked': False,
            'response_time_acceptable': False
        }
        
        # IP format check
        if self.framework.validate_ip(ip):
            validation_results['ip_format_valid'] = True
            self.framework.print_status(StatusLevel.SUCCESS, 
                f"IP format valid: {ip}")
        else:
            self.framework.print_status(StatusLevel.ERROR, 
                f"Invalid IP format: {ip}")
            return validation_results
            
        # Reachability check
        if self.framework.check_ip_reachability(ip, port):
            validation_results['ip_reachable'] = True
            validation_results['port_open'] = True
            self.framework.print_status(StatusLevel.SUCCESS, 
                f"IP reachable: {ip}:{port}")
        else:
            self.framework.print_status(StatusLevel.WARN, 
                f"IP not reachable: {ip}:{port}")
            
        # SSH service check
        is_ssh, banner, response_time = self.framework.grab_ssh_banner(ip, port)
        if is_ssh:
            validation_results['ssh_service'] = True
            self.framework.print_status(StatusLevel.SUCCESS, 
                f"SSH service detected: {banner[:50]}...")
                
            # Response time check
            if response_time < 1000:  # Less than 1 second
                validation_results['response_time_acceptable'] = True
                self.framework.print_status(StatusLevel.SUCCESS, 
                    f"Response time acceptable: {response_time:.1f}ms")
            else:
                self.framework.print_status(StatusLevel.WARN, 
                    f"Slow response time: {response_time:.1f}ms")
        else:
            self.framework.print_status(StatusLevel.WARN, 
                f"No SSH service on {ip}:{port}")
            
        # Firewall test (simplified)
        if validation_results['ip_reachable'] and not validation_results['ssh_service']:
            validation_results['firewall_blocked'] = True
            self.framework.print_status(StatusLevel.WARN, 
                "Possible firewall blocking detected")
            
        return validation_results
        
    def get_system_info(self) -> Dict[str, str]:
        """Collect system information"""
        info = {
            'platform': platform.platform(),
            'python_version': f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
            'architecture': platform.architecture()[0],
            'processor': platform.processor(),
            'hostname': platform.node(),
            'current_user': os.getenv('USER', os.getenv('USERNAME', 'unknown')),
            'working_directory': os.getcwd(),
            'timestamp': datetime.now().isoformat()
        }
        
        # Network information
        try:
            info['public_ip'] = self.framework.get_public_ip() or "Not available"
        except:
            info['public_ip'] = "Error determining"
            
        # Memory information
        try:
            memory = psutil.virtual_memory()
            info['total_memory'] = f"{memory.total / (1024**3):.1f} GB"
            info['available_memory'] = f"{memory.available / (1024**3):.1f} GB"
        except:
            info['total_memory'] = "Not available"
            info['available_memory'] = "Not available"
            
        # Disk information
        try:
            disk_usage = psutil.disk_usage('/')
            info['total_disk'] = f"{disk_usage.total / (1024**3):.1f} GB"
            info['free_disk'] = f"{disk_usage.free / (1024**3):.1f} GB"
        except:
            info['total_disk'] = "Not available"
            info['free_disk'] = "Not available"
            
        return info
        
    def display_system_status(self):
        """Display detailed system status"""
        print(f"\n{Colors.BOLD}╔═══════════════ System Status ═══════════════╗{Colors.RESET}")
        
        # Collect system information
        system_info = self.get_system_info()
        
        # Basic information
        print(f"║ Platform:        {system_info['platform']:<30} ║")
        print(f"║ Python:          {system_info['python_version']:<30} ║")
        print(f"║ Architecture:    {system_info['architecture']:<30} ║")
        print(f"║ Hostname:        {system_info['hostname']:<30} ║")
        print(f"║ User:            {system_info['current_user']:<30} ║")
        print(f"║ Working Dir:     {system_info['working_directory']:<30} ║")
        print(f"║ Public IP:       {system_info['public_ip']:<30} ║")
        print(f"║ Memory:          {system_info['available_memory']:<30} ║")
        print(f"║ Disk Space:      {system_info['free_disk']:<30} ║")
        
        print(f"╚══════════════════════════════════════════════╝\n")
        
        # Available tools
        print(f"{Colors.BOLD}Available Network Tools:{Colors.RESET}")
        
        tools_status = self._check_network_tools_detailed()
        for tool, status in tools_status.items():
            status_color = Colors.GREEN if status else Colors.RED
            status_text = "✓" if status else "✗"
            print(f"  {status_color}{status_text}{Colors.RESET} {tool}")
            
        # System requirements
        print(f"\n{Colors.BOLD}System Requirements:{Colors.RESET}")
        requirements = self.check_system_requirements()
        
        for requirement, status in requirements.items():
            status_color = Colors.GREEN if status else Colors.RED
            status_text = "✓" if status else "✗"
            print(f"  {status_color}{status_text}{Colors.RESET} {requirement.replace('_', ' ').title()}")
            
    def _check_network_tools_detailed(self) -> Dict[str, bool]:
        """Detailed check of network tools"""
        tools = ['nc', 'ncat', 'netcat', 'socat', 'curl', 'wget', 'ping', 'nmap', 'netstat']
        results = {}
        
        for tool in tools:
            try:
                result = subprocess.run([tool, '--version'], 
                                      capture_output=True, timeout=3)
                results[tool] = result.returncode == 0
            except (subprocess.TimeoutExpired, FileNotFoundError):
                results[tool] = False
                
        return results
        
    def install_missing_dependencies(self):
        """Install missing dependencies"""
        self.framework.print_status(StatusLevel.INFO, 
            "Checking and installing missing dependencies...")
            
        # Python packages
        required_packages = ['requests', 'psutil']
        
        for package in required_packages:
            try:
                __import__(package)
                self.framework.print_status(StatusLevel.SUCCESS, 
                    f"Package {package} already installed")
            except ImportError:
                self.framework.print_status(StatusLevel.INFO, 
                    f"Installing package {package}...")
                try:
                    subprocess.run([sys.executable, '-m', 'pip', 'install', package], 
                                 check=True)
                    self.framework.print_status(StatusLevel.SUCCESS, 
                        f"Package {package} successfully installed")
                except subprocess.CalledProcessError as e:
                    self.framework.print_status(StatusLevel.ERROR, 
                        f"Error installing {package}: {e}")
                        
        # System tools (Linux/Unix)
        if platform.system() in ['Linux', 'Darwin']:
            system_tools = {
                'netcat-openbsd': 'nc',
                'nmap': 'nmap',
                'curl': 'curl',
                'socat': 'socat'
            }
            
            for package, command in system_tools.items():
                try:
                    subprocess.run([command, '--version'], 
                                 capture_output=True, check=True)
                    self.framework.print_status(StatusLevel.SUCCESS, 
                        f"Tool {command} already available")
                except (subprocess.CalledProcessError, FileNotFoundError):
                    self.framework.print_status(StatusLevel.INFO, 
                        f"Tool {command} not available - manual installation required")
                    self.framework.print_status(StatusLevel.INFO, 
                        f"Installation: sudo apt install {package} (Ubuntu/Debian)")
                    
    def create_system_report(self, filename: str = None) -> str:
        """Create detailed system report"""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"system_report_{timestamp}.json"
            
        try:
            report = {
                'timestamp': datetime.now().isoformat(),
                'system_info': self.get_system_info(),
                'requirements_check': self.check_system_requirements(),
                'network_tools': self._check_network_tools_detailed(),
                'framework_config': {
                    'listener_port': 4444,
                    'max_threads': 50,
                    'timeout': 5,
                    'supported_cves': [
                        'CVE-2024-6387',
                        'CVE-2020-14145',
                        'CVE-2021-28041',
                        'CVE-2019-16905',
                        'CVE-2018-15473'
                    ]
                }
            }
            
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(report, f, indent=2, ensure_ascii=False)
                
            self.framework.print_status(StatusLevel.SUCCESS, 
                f"System report created: {filename}")
            return filename
            
        except Exception as e:
            self.framework.print_status(StatusLevel.ERROR, 
                f"Error creating system report: {e}")
            return ""
