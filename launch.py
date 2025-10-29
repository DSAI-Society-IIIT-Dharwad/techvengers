#!/usr/bin/env python3
"""
Main Launcher for Network Security Dashboard
Organized workspace launcher
"""

import os
import sys
from pathlib import Path

def main():
    """Main launcher function"""
    print("=" * 60)
    print("NETWORK SECURITY DASHBOARD")
    print("=" * 60)
    print("Organized Workspace Launcher")
    print()
    
    # Get the script directory
    script_dir = Path(__file__).parent
    
    # Check if desktop app exists
    desktop_app = script_dir / "desktop-app" / "start_desktop_dashboard.py"
    if desktop_app.exists():
        print("🚀 Starting Desktop Application...")
        print("   Location: desktop-app/start_desktop_dashboard.py")
        print()
        
        # Change to desktop-app directory and run
        os.chdir(script_dir / "desktop-app")
        os.system(f"{sys.executable} start_desktop_dashboard.py")
    else:
        print("❌ Desktop application not found!")
        print("   Expected location: desktop-app/start_desktop_dashboard.py")
        print()
        print("Available options:")
        print("1. Run desktop app: cd desktop-app && python start_desktop_dashboard.py")
        print("2. Run ML tests: cd tests/ml-tests && python test_anomaly_detection.py")
        print("3. View documentation: docs/guides/")
        print("4. Check utilities: scripts/utilities/")

if __name__ == "__main__":
    main()
