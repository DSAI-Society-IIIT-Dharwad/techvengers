#!/usr/bin/env python3
"""
Desktop Dashboard Launcher
Simple launcher for the Network Security Desktop Dashboard
"""

import subprocess
import sys
import os
from pathlib import Path

def main():
    """Launch the desktop dashboard"""
    print("Network Security Desktop Dashboard")
    print("=" * 50)
    print("Starting desktop application...")
    print("Loading ML models...")
    print("Initializing GUI...")
    print("Starting real-time monitoring...")
    print()
    print("Features available:")
    print("- Real-time network monitoring")
    print("- ML-powered threat detection")
    print("- Interactive threat injection testing")
    print("- Live anomaly detection")
    print()
    print("The desktop application should open in a new window.")
    print("If it doesn't appear, check the console for any error messages.")
    print()
    
    try:
        # Get the script directory
        script_dir = Path(__file__).parent
        dashboard_script = script_dir / "network_dashboard_desktop.py"
        
        if not dashboard_script.exists():
            print("Error: network_dashboard_desktop.py not found!")
            print(f"Expected location: {dashboard_script}")
            return False
        
        # Start the desktop application
        print("Launching desktop dashboard...")
        subprocess.run([sys.executable, str(dashboard_script)])
        
    except KeyboardInterrupt:
        print("\nDashboard closed by user")
    except Exception as e:
        print(f"Error starting dashboard: {e}")
        return False
    
    return True

if __name__ == "__main__":
    main()

