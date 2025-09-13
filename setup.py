#!/usr/bin/env python3
"""
NO REGRESSH - Setup Script
Automatic installation and configuration of the framework
"""

import os
import sys
import subprocess
import platform
from pathlib import Path

def print_banner():
    """Show setup banner"""
    banner = """
╔══════════════════════════════════════════════════════════════════╗
║                                                                  ║
║    NO REGRESSH - Enhanced Framework Setup                        ║
║    CVE-2024-6387 Scanner & Exploit Tool                        ║
║                                                                  ║
║    ⚠️  For authorized penetration testing only! ⚠️              ║
║                                                                  ║
╚══════════════════════════════════════════════════════════════════╝
"""
    print(banner)

def check_python_version():
    """Check Python version"""
    print("🔍 Checking Python version...")
    
    version = sys.version_info
    if version >= (3, 7):
        print(f"✅ Python {version.major}.{version.minor}.{version.micro} - OK")
        return True
    else:
        print(f"❌ Python {version.major}.{version.minor}.{version.micro} - Too old!")
        print("   Minimum Python 3.7 required")
        return False

def install_python_dependencies():
    """Install Python dependencies"""
    print("\n📦 Installing Python dependencies...")
    
    requirements_file = Path("requirements.txt")
    if not requirements_file.exists():
        print("❌ requirements.txt not found")
        return False
        
    try:
        subprocess.run([
            sys.executable, "-m", "pip", "install", "-r", "requirements.txt"
        ], check=True)
        print("✅ Python dependencies installed")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ Error installing dependencies: {e}")
        return False

def check_system_tools():
    """Check available system tools"""
    print("\n🔧 Checking system tools...")
    
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
            result = subprocess.run(cmd.split(), capture_output=True, timeout=5)
            if result.returncode == 0:
                available_tools.append(tool)
                print(f"✅ {tool} - Available")
            else:
                print(f"⚠️  {tool} - Not available")
        except (subprocess.TimeoutExpired, FileNotFoundError):
            print(f"❌ {tool} - Not found")
    
    return available_tools

def install_system_tools():
    """Install missing system tools"""
    print("\n🛠️  Installing missing system tools...")
    
    system = platform.system().lower()
    
    if system == "linux":
        # Ubuntu/Debian
        if os.path.exists("/etc/debian_version"):
            print("📋 Ubuntu/Debian detected")
            tools_to_install = [
                "curl",
                "netcat-openbsd", 
                "nmap",
                "wget",
                "socat"
            ]
            
            for tool in tools_to_install:
                print(f"   Installing {tool}...")
                try:
                    subprocess.run([
                        "sudo", "apt", "update"
                    ], check=True, timeout=30)
                    
                    subprocess.run([
                        "sudo", "apt", "install", "-y", tool
                    ], check=True, timeout=60)
                    
                    print(f"   ✅ {tool} installed")
                except subprocess.CalledProcessError:
                    print(f"   ❌ Error installing {tool}")
                except subprocess.TimeoutExpired:
                    print(f"   ⏰ Timeout installing {tool}")
                    
        # CentOS/RHEL
        elif os.path.exists("/etc/redhat-release"):
            print("📋 CentOS/RHEL detected")
            tools_to_install = [
                "curl",
                "nc",
                "nmap",
                "wget",
                "socat"
            ]
            
            for tool in tools_to_install:
                print(f"   Installing {tool}...")
                try:
                    subprocess.run([
                        "sudo", "yum", "install", "-y", tool
                    ], check=True, timeout=60)
                    
                    print(f"   ✅ {tool} installed")
                except subprocess.CalledProcessError:
                    print(f"   ❌ Error installing {tool}")
                except subprocess.TimeoutExpired:
                    print(f"   ⏰ Timeout installing {tool}")
                    
    elif system == "darwin":  # macOS
        print("📋 macOS detected")
        print("   Using Homebrew for tool installation...")
        
        tools_to_install = [
            "curl",
            "netcat",
            "nmap",
            "socat"
        ]
        
        for tool in tools_to_install:
            print(f"   Installing {tool}...")
            try:
                subprocess.run([
                    "brew", "install", tool
                ], check=True, timeout=60)
                
                print(f"   ✅ {tool} installed")
            except subprocess.CalledProcessError:
                print(f"   ❌ Error installing {tool}")
            except subprocess.TimeoutExpired:
                print(f"   ⏰ Timeout installing {tool}")
                
    else:
        print(f"⚠️  Unknown system: {system}")
        print("   Manual tool installation required")

def create_directories():
    """Create required directories"""
    print("\n📁 Creating directories...")
    
    directories = [
        "logs",
        "reports", 
        "exports"
    ]
    
    for directory in directories:
        Path(directory).mkdir(exist_ok=True)
        print(f"   ✅ {directory}/")

def create_launcher_script():
    """Create launcher script"""
    print("\n🚀 Creating launcher script...")
    
    launcher_content = """#!/usr/bin/env python3
\"\"\"
NO REGRESSH Launcher Script
Automatic framework startup
\"\"\"

import sys
import os
from pathlib import Path

# Add framework directory to Python path
framework_dir = Path(__file__).parent
sys.path.insert(0, str(framework_dir))

try:
    from no_regresh_menu import MenuSystem
    
    if __name__ == "__main__":
        print("🚀 Starting NO REGRESSH Framework...")
        menu = MenuSystem()
        menu.run()
        
except ImportError as e:
    print(f"❌ Error importing framework: {e}")
    print("   Make sure all dependencies are installed:")
    print("   pip install -r requirements.txt")
    sys.exit(1)
except Exception as e:
    print(f"❌ Unexpected error: {e}")
    sys.exit(1)
"""
    
    launcher_file = Path("no_regresh_launcher.py")
    launcher_file.write_text(launcher_content, encoding='utf-8')
    
    # Make executable (Unix/Linux/macOS)
    if platform.system() != "Windows":
        os.chmod(launcher_file, 0o755)
    
    print("   ✅ no_regresh_launcher.py created")

def run_system_check():
    """Run system check"""
    print("\n🔍 Running system check...")
    
    try:
        # Import and run system check
        sys.path.insert(0, str(Path.cwd()))
        from no_regresh_system import SystemChecker
        from no_regresh_main import NoRegreshFramework
        
        framework = NoRegreshFramework()
        checker = SystemChecker(framework)
        
        requirements = checker.check_system_requirements()
        
        print("\n📊 System Check Results:")
        passed = sum(requirements.values())
        total = len(requirements)
        
        for requirement, status in requirements.items():
            status_icon = "✅" if status else "❌"
            print(f"   {status_icon} {requirement.replace('_', ' ').title()}")
            
        print(f"\n📈 Total: {passed}/{total} tests passed")
        
        if passed == total:
            print("🎉 All system requirements met!")
            return True
        else:
            print("⚠️  Some requirements not met")
            return False
            
    except Exception as e:
        print(f"❌ Error during system check: {e}")
        return False

def main():
    """Main setup script function"""
    print_banner()
    
    print("🚀 NO REGRESSH Framework Setup")
    print("=" * 50)
    
    # Check Python version
    if not check_python_version():
        print("\n❌ Setup cancelled - Python version too old")
        sys.exit(1)
    
    # Install Python dependencies
    if not install_python_dependencies():
        print("\n❌ Setup cancelled - Dependencies could not be installed")
        sys.exit(1)
    
    # Check system tools
    available_tools = check_system_tools()
    
    # Install missing tools
    if len(available_tools) < 3:  # At least curl, netcat, and one other
        install_choice = input("\n🛠️  Install missing system tools? (y/N): ").lower().strip()
        if install_choice in ['y', 'yes']:
            install_system_tools()
        else:
            print("⚠️  Manual tool installation required")
    
    # Create directories
    create_directories()
    
    # Create launcher script
    create_launcher_script()
    
    # Run system check
    system_ok = run_system_check()
    
    # Summary
    print("\n" + "=" * 50)
    print("🎯 Setup Summary:")
    print("   ✅ Python dependencies installed")
    print("   ✅ Directories created")
    print("   ✅ Launcher script created")
    
    if system_ok:
        print("   ✅ System check passed")
        print("\n🚀 Framework ready for use!")
        print("   Start with: python no_regresh_launcher.py")
    else:
        print("   ⚠️  System check with warnings")
        print("\n⚠️  Framework can be used with limitations")
        print("   Start with: python no_regresh_launcher.py")
    
    print("\n📚 Additional Information:")
    print("   - Logs are stored in logs/")
    print("   - Reports are stored in reports/")
    print("   - Exports are stored in exports/")
    print("\n⚠️  IMPORTANT: Use only for authorized penetration testing!")

if __name__ == "__main__":
    main()
