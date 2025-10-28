#!/usr/bin/env python3
"""
Dashboard Launcher
=================

Simple launcher script to start the Streamlit dashboard.
"""

import subprocess
import sys
import os

def run_dashboard():
    """Run the Streamlit dashboard."""
    print("Starting Network Traffic Analyzer Dashboard...")
    print("=" * 50)
    
    # Change to project root directory
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    os.chdir(project_root)
    
    print("Available dashboards:")
    print("1. Basic Dashboard (src/dashboard.py)")
    print("2. Enhanced Dashboard with GeoIP (src/enhanced_dashboard.py)")
    
    choice = input("\nEnter your choice (1-2): ").strip()
    
    if choice == "1":
        dashboard_file = "src/dashboard.py"
        print(f"\nStarting basic dashboard: {dashboard_file}")
    elif choice == "2":
        dashboard_file = "src/enhanced_dashboard.py"
        print(f"\nStarting enhanced dashboard: {dashboard_file}")
    else:
        dashboard_file = "src/enhanced_dashboard.py"
        print(f"\nInvalid choice. Starting enhanced dashboard: {dashboard_file}")
    
    try:
        # Run Streamlit
        subprocess.run([
            sys.executable, "-m", "streamlit", "run", dashboard_file,
            "--server.port", "8501",
            "--server.address", "localhost",
            "--browser.gatherUsageStats", "false"
        ], check=True)
    except subprocess.CalledProcessError as e:
        print(f"Error running dashboard: {e}")
        print("Make sure Streamlit is installed: pip install streamlit")
    except KeyboardInterrupt:
        print("\nDashboard stopped by user.")

if __name__ == "__main__":
    run_dashboard()
