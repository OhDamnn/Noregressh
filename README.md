# NO REGRESSH - Enhanced CVE-2024-6387 Framework

A complete Python framework for CVE-2024-6387 scanning and exploitation with advanced features for authorized penetration testing.

## 🚀 Quick Start

### 1. Automatic Installation
```bash
# Download framework and start setup
python setup.py
```

### 2. Manual Installation
```bash
# Install dependencies
pip install -r requirements.txt

# Start framework
python no_regresh_launcher.py
```

## ✨ New Features (Python Version)

### **Enhanced Status Messages**
- **Detailed Debug Information**: Complete logging of all operations
- **Improved Error Handling**: Precise error messages with solution suggestions
- **Real-time Progress Tracking**: Live updates for all operations
- **Structured Logs**: JSON-formatted logs for better analysis

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

## 🎯 Main Modules

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
- Python-based listeners (alternative to Netcat)
- Interactive shell sessions
- Multi-port support
- Automatic connection monitoring
- File transfer capabilities
- Screenshot and keylogging features

### **4. System Status**
- Complete system verification
- IP configuration validation
- Dependency management
- System reports and logs
- Firewall and antivirus detection

### **5. Log Viewer**
- Real-time log monitoring
- Log search and filtering
- Automatic log rotation
- Export functions

## 📋 Menu Navigation

```
╔═══════════════════ Main Menu ═══════════════════╗
║  1) 🔍 Network Scanner                          ║
║     (SSH Services & Vulnerability Scan)         ║
║  2) 💥 Targeted Exploitation                     ║
║     (CVE-2024-6387 & Other SSH Exploits)       ║
║  3) 📊 Listener Management                       ║
║     (Python, Netcat & Socat Listeners)         ║
║  4) ⚙️ System Status                            ║
║     (System Check & Configuration)              ║
║  5) 📁 Log Viewer                               ║
║     (Session Logs & Reports)                    ║
║  6) ❌ Exit                                      ║
╚═════════════════════════════════════════════════╝
```

## 🔧 Usage

### **Scanner Mode**
1. **Network Scanner** selection
2. **IP Range** or **Single Target** configuration
3. **Thread Count** adjustment (1-50)
4. **CVE Selection** (All, Specific, or Custom)
5. **Start Scan** and analyze results
6. **CSV Export** for further analysis

### **Exploit Mode**
1. **Targeted Exploitation** selection
2. **Target IP and Port** input
3. **CVE Selection**:
   - CVE-2024-6387 (regreSSHion) - Remote Code Execution
   - CVE-2020-14145 - Username Enumeration
   - CVE-2021-28041 - Username Enumeration
   - CVE-2019-16905 - Username Enumeration
   - CVE-2018-15473 - Username Enumeration
4. **Payload Selection** (for RCE CVEs):
   - Reverse Shell (recommended)
   - Bind Shell
   - Custom Shellcode
   - Web Shell
   - Generic Exploit
5. **Listener Configuration** (Python, Netcat, or Socat)
6. **Execute Exploit** with detailed monitoring

### **Listener Management**
- **Python Listener**: Complete alternative to Netcat with advanced features
- **Interactive Shell**: Direct command execution with security checks
- **Multi-Port Support**: Simultaneous management of multiple ports
- **Automatic Monitoring**: Status updates and connection tracking
- **File Transfer**: Upload/download files through connections
- **Screenshot**: Take screenshots on target systems
- **Keylogger**: Basic keylogging functionality

## 📊 Enhanced Output

### **Detailed Status Messages**
```
[15:23:45] [INFO] Starting exploit against 192.168.1.100:22
[15:23:45] [DEBUG] Attempt 1: Connecting to 192.168.1.100:22
[15:23:45] [INFO] Banner received: SSH-2.0-OpenSSH_8.9p1 Ubuntu-4ubuntu0.2
[15:23:45] [VULN] CVE-2024-6387 vulnerable version detected: OpenSSH_8.9
[15:23:45] [DEBUG] SSH identification sent
[15:23:45] [INFO] Starting reverse shell exploit sequence...
[15:23:45] [DEBUG] Exploit round 1/5
[15:23:46] [SUCCESS] Exploit payload successfully sent (attempt 1)
[15:23:46] [SUCCESS] Reverse shell exploit payload fully transmitted
```

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

## 🛡️ Supported Vulnerable Versions

The framework detects the following known vulnerable OpenSSH versions:
- OpenSSH 8.5 - 9.7 (CVE-2024-6387)
- OpenSSH 8.2 - 8.3 (CVE-2021-28041)
- OpenSSH 7.4 - 7.5 (CVE-2020-14145)
- OpenSSH 7.9 - 8.0 (CVE-2019-16905)
- OpenSSH 7.7 - 7.8 (CVE-2018-15473)

## 📁 File Structure

```
Final_Eng_No_Regress/
├── no_regresh_main.py          # Main framework class
├── no_regresh_scanner.py       # Network scanner module
├── no_regresh_exploit.py       # Exploit module with payloads
├── no_regresh_listener.py      # Advanced listener functions
├── no_regresh_system.py        # System check and management
├── no_regresh_menu.py          # Main menu system
├── no_regresh_launcher.py     # Launcher script (after setup)
├── setup.py                    # Automatic setup script
├── requirements.txt            # Python dependencies
├── README.md                   # This documentation
├── logs/                       # Session logs
├── reports/                    # System reports
└── exports/                    # Scan exports
```

## ⚠️ Important Notes

### **For Authorized Testing Only!**
- This tool is exclusively for authorized penetration testing
- Use against foreign systems without permission is illegal
- Users are responsible for lawful use

### **System Requirements**
- Python 3.7+ (recommended: 3.9+)
- Linux/macOS/Windows (Linux recommended)
- At least 1 GB free disk space
- Network access for scans and exploits

### **Improvements over C Version**
- ✅ **No Memory Leaks**: Automatic memory management
- ✅ **Better Error Handling**: Detailed exception handling
- ✅ **Thread Safety**: Improved multi-threading implementation
- ✅ **Extended Logs**: Structured logging
- ✅ **Modular Architecture**: Clean code separation
- ✅ **Cross-Platform**: Works on all operating systems
- ✅ **Automatic Setup**: One-click installation
- ✅ **Extended Payloads**: More exploit options
- ✅ **Multiple CVEs**: Support for various SSH vulnerabilities
- ✅ **Advanced Listeners**: Python, Netcat, and Socat support
- ✅ **Post-Exploitation**: Comprehensive post-exploit actions

## 🔧 Troubleshooting

### **Setup Issues**
```bash
# Install dependencies manually
pip install requests psutil

# Install system tools (Ubuntu/Debian)
sudo apt update && sudo apt install netcat-openbsd nmap curl socat

# Check permissions
chmod +x no_regresh_launcher.py
```

### **Listener Issues**
- **Port already in use**: `netstat -tulpn | grep :4444`
- **Firewall blocking**: Check IPTables/UFW rules
- **Use Python listener**: Alternative to Netcat

### **Exploit Issues**
- **Target not reachable**: Check network connectivity
- **No vulnerable version**: Verify banner analysis
- **Timing issues**: Adjust delay values

## 📈 Performance Optimization

### **Scanner Performance**
- Adjust thread count to CPU cores (recommended: CPU Cores × 2)
- Use smaller IP ranges for faster results
- Adjust timeout values for slow networks

### **Memory Management**
- Automatic memory management through Python
- Regular log rotation
- CSV exports for very large datasets

## 🤝 Contributing

Improvements and bug reports are welcome:

1. **Code Improvements** in Python modules
2. **Setup Script Optimizations**
3. **Documentation Updates**
4. **Additional Payload Options**
5. **OS-specific Improvements**

## 📄 License

This tool is developed for educational and authorized penetration testing purposes. 
The author assumes no responsibility for misuse.

---

**Developed for professional penetration testers and security researchers**

**NO REGRESSH - Enhanced CVE-2024-6387 Framework v3.0**
