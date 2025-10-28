#!/usr/bin/env python3
"""
Network Traffic Analyzer - Quick Launcher
=========================================

Simple launcher script to quickly start packet capture with WiFi authentication support.
"""

import os
import sys
import subprocess


def run_script(script_path):
    """Run a Python script with proper path handling."""
    try:
        # Change to project root directory
        project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        os.chdir(project_root)
        
        # Run the script
        result = subprocess.run([sys.executable, script_path], check=True)
        return result.returncode == 0
    except subprocess.CalledProcessError as e:
        print(f"Error running {script_path}: {e}")
        return False
    except FileNotFoundError:
        print(f"Script not found: {script_path}")
        return False


def main():
    """Quick launcher for the network traffic analyzer."""
    print("Network Traffic Analyzer - Quick Launcher")
    print("=" * 50)
    
    print("\nAvailable options:")
    print("1. Test WiFi authentication")
    print("2. Start packet capture (with auth check)")
    print("3. Run network diagnostics")
    print("4. Analyze existing packet data")
    print("5. Run streaming analyzer")
    print("6. Test saved models")
    print("7. Launch Security Dashboard")
    
    choice = input("\nEnter your choice (1-7): ").strip()
    
    if choice == "1":
        print("\nTesting WiFi authentication...")
        run_script("src/wifi_auth_handler.py")
        
    elif choice == "2":
        print("\nStarting packet capture...")
        print("This will check for WiFi authentication and start capturing packets.")
        run_script("src/working_packet_sniffer.py")
        
    elif choice == "3":
        print("\nRunning network diagnostics...")
        run_script("scripts/network_check.py")
        
    elif choice == "4":
        print("\nAnalyzing existing packet data...")
        if os.path.exists("data/packets_extended.csv"):
            run_script("src/analyzer.py")
        else:
            print("No packet data found. Run packet capture first.")
    
    elif choice == "5":
        print("\nRunning streaming analyzer...")
        run_script("src/streaming_analyzer.py")
        
    elif choice == "6":
        print("\nTesting saved models...")
        run_script("scripts/test_saved_models.py")
    
    elif choice == "7":
        print("\nLaunching Security Dashboard...")
        run_script("scripts/dashboard_launcher.py")
    
    else:
        print("Invalid choice. Starting packet capture by default...")
        run_script("src/working_packet_sniffer.py")


if __name__ == "__main__":
    main()
