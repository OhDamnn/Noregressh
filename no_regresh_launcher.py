#!/usr/bin/env python3
"""
NO REGRESSH Launcher Script
Automatic framework startup
"""

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
