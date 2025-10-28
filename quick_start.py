#!/usr/bin/env python3
"""
Quick Server Starter
Simple script to quickly start both backend and frontend servers
"""

import subprocess
import time
import sys
import os
from pathlib import Path

def start_servers():
    """Start both backend and frontend servers"""
    print("Starting Network Dashboard Servers...")
    
    # Get project paths
    project_root = Path(__file__).parent
    web_app_dir = project_root / "web-app"
    react_app_dir = web_app_dir / "network-dashboard"
    
    processes = []
    
    try:
        # Start backend server
        print("Starting backend server (port 8000)...")
        backend_process = subprocess.Popen(
            [sys.executable, "realtime_api_server.py"],
            cwd=web_app_dir
        )
        processes.append(backend_process)
        
        # Wait a moment
        time.sleep(2)
        
        # Start frontend server
        print("Starting frontend server (port 3000)...")
        frontend_process = subprocess.Popen(
            ["npm", "start"],
            cwd=react_app_dir
        )
        processes.append(frontend_process)
        
        print("\n✓ Both servers are starting...")
        print("✓ Backend: http://localhost:8000")
        print("✓ Frontend: http://localhost:3000")
        print("\nPress Ctrl+C to stop all servers")
        
        # Wait for processes
        while True:
            time.sleep(1)
            # Check if any process died
            for i, process in enumerate(processes):
                if process.poll() is not None:
                    print(f"Process {i+1} stopped unexpectedly")
                    return False
                    
    except KeyboardInterrupt:
        print("\nStopping servers...")
        for process in processes:
            process.terminate()
        print("✓ All servers stopped")
        return True
    except Exception as e:
        print(f"Error: {e}")
        for process in processes:
            process.terminate()
        return False

if __name__ == "__main__":
    start_servers()
