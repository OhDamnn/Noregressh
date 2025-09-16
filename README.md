

### **Multiple CVE Support**
- **CVE-2024-6387**: Remote Code Execution (regreSSHion)
- **CVE-2020-14145**: Username Enumeration via Timing Attack
- **CVE-2021-28041**: Username Enumeration via Response Timing
- **CVE-2019-16905**: Username Enumeration via Error Messages
- **CVE-2018-15473**: Username Enumeration via Response Differences

##  Quick Start

### 1. Automatic Installation
```bash
# Download framework and start setup
python setup.py
```

### 2. Manual Installation

# Install dependencies
pip install -r requirements.txt

# Start framework
python no_regresh_launcher.py
```

Features 

### **Enhanced Status Messages**
- **Detailed Debug Information**: Complete logging of all operations
### **Advanced Listener Functions**
- **Python Listener**: Complete alternative to Netcat with enhanced features
- **Interactive Shell**: Direct command execution with security checks
- **Multi-Listener Support**: Simultaneous management of multiple listeners
- **Automatic Fallback**: Switch between Python, Netcat, and Socat listeners
- **File Transfer**: Upload/download files through listener connections
- **Screenshot Capture**: Take screenshots on target systems
- **Keylogger**: Basic keylogging functionality
### **Extended Payload Options**
- **Reverse Shell**: Bash, Python, PowerShell, Perl, and Base64-encoded variants
- **Bind Shell**: Automatic port configuration
- **Custom Shellcode**: x64 shellcode with NOP-sled
- **Web Shell**: PHP web shell for web-based targets
- **Generic Exploits**: Customizable exploit patterns

### **Advanced System Verification**
- **IP Validation**: Complete reachability check before exploit
- **Firewall Detection**: Automatic detection of blocking mechanisms
- **Dependency Check**: Automatic installation of missing dependencies
- **System Reports**: Detailed JSON reports for documentation
- **Antivirus Detection**: Check for common antivirus software

### **Multiple CVE Support**
- **CVE-2024-6387**: Remote Code Execution (regreSSHion)
- **CVE-2020-14145**: Username Enumeration via Timing Attack
- **CVE-2021-28041**: Username Enumeration via Response Timing
- **CVE-2019-16905**: Username Enumeration via Error Messages
- **CVE-2018-15473**: Username Enumeration via Response Differences




 Main Modules

### **1. Network Scanner**
- Multi-threading SSH service discovery
- Automatic vulnerability detection for multiple CVEs
- IP range and single target scans
- CSV export for further analysis
- Custom CVE selection

### **2. Targeted Exploitation**
- CVE-2024-6387 exploit with various payloads
- Automatic listener configuration
- Timing-optimized exploit sequences
- Success tracking and statistics
- Post-exploitation actions

### **3. Listener Management**
### **4. System Status**
### **5. Log Viewer**
### **Listener Management**
##  Enhanced Output
### **Detailed Status Messages**
##  Menu Navigation

```
╔═══════════════════ Main Menu ═══════════════════╗
║  1) Network Scanner                          ║
║     (SSH Services & Vulnerability Scan)         ║
║  2) Targeted Exploitation                     ║
║     (CVE-2024-6387 & Other SSH Exploits)       ║
║  3) Listener Management                       ║
║     (Python, Netcat & Socat Listeners)         ║
║  4) System Status                            ║
║     (System Check & Configuration)              ║
║  5) Log Viewer                               ║
║     (Session Logs & Reports)                    ║
║  6) Exit                                      ║
╚═════════════════════════════════════════════════╝

### **System Status**
```
╔═══════════════ System Status ═══════════════╗
║ Platform:        Linux-5.4.0-74-generic     ║
║ Python:          3.9.7                      ║
║ Architecture:     64bit                      ║
║ Hostname:        pentest-box                ║
║ User:            pentester                  ║
║ Public IP:       203.0.113.42              ║
║ Memory:          7.2 GB                     ║
║ Disk Space:      45.2 GB                    ║
╚══════════════════════════════════════════════╝
```

Supported Vulnerable Versions

The framework detects the following known vulnerable OpenSSH versions:
- OpenSSH 8.5 - 9.7 (CVE-2024-6387)
- OpenSSH 8.2 - 8.3 (CVE-2021-28041)
- OpenSSH 7.4 - 7.5 (CVE-2020-14145)
- OpenSSH 7.9 - 8.0 (CVE-2019-16905)
- OpenSSH 7.7 - 7.8 (CVE-2018-15473)

# Important Notes

### **For Authorized Testing Only!**
- This tool is exclusively for authorized penetration testing
- Use against foreign systems without permission is illegal
- Users are responsible for lawful use
- **No Memory Leaks**: Automatic memory management
- **Better Error Handling**: Detailed exception handling
- **Thread Safety**: Improved multi-threading implementation
- **Extended Logs**: Structured logging


Troubleshooting

Setup Issues???

# Check permissions
chmod +x no_regresh_launcher.py

COded by me with ai.
