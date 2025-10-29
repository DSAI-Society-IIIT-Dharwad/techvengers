#!/usr/bin/env python3
"""
Web Dashboard Launcher
Web version of the Network Security Dashboard
"""

import subprocess
import sys
import os
from pathlib import Path

def main():
    """Launch the web dashboard"""
    print("Network Security Web Dashboard")
    print("=" * 50)
    print("Starting web application...")
    print("Loading ML models...")
    print("Initializing web interface...")
    print("Starting real-time monitoring...")
    print()
    print("Features available:")
    print("- Real-time network packet capture from WiFi")
    print("- ML-powered threat detection (500+ sample training)")
    print("- Enhanced device tracking with MAC addresses")
    print("- Professional device monitoring dashboard")
    print("- Interactive threat injection testing")
    print("- Live anomaly detection with training progress")
    print("- Network topology visualization")
    print("- Bandwidth usage tracking")
    print("- Professional web UI with status indicators")
    print()
    print("The web application will be available at:")
    print("http://localhost:5000")
    print()
    
    try:
        # Get the script directory
        script_dir = Path(__file__).parent
        web_app_script = script_dir / "web_dashboard.py"
        
        if not web_app_script.exists():
            print("Error: web_dashboard.py not found!")
            print(f"Expected location: {web_app_script}")
            return False
        
        # Start the web application
        print("Launching web dashboard...")
        subprocess.run([sys.executable, str(web_app_script)])
        
    except KeyboardInterrupt:
        print("\nWeb dashboard closed by user")
    except Exception as e:
        print(f"Error starting web dashboard: {e}")
        return False
    
    return True

if __name__ == "__main__":
    main()
