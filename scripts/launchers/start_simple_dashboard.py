#!/usr/bin/env python3
"""
Simple Dashboard Launcher
Starts both the Node.js backend and serves the HTML dashboard
"""

import subprocess
import webbrowser
import time
import os
import sys
from pathlib import Path

def start_nodejs_backend():
    """Start the Node.js backend server"""
    print("Starting Node.js backend server...")
    
    web_app_dir = Path(__file__).parent / "web-app"
    server_js = web_app_dir / "server.js"
    
    if not server_js.exists():
        print("Error: server.js not found!")
        return None
    
    try:
        process = subprocess.Popen(
            ["node", str(server_js)],
            cwd=str(web_app_dir),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        
        # Wait a moment for server to start
        time.sleep(3)
        
        if process.poll() is None:
            print("✓ Node.js backend started successfully on port 8000")
            return process
        else:
            stdout, stderr = process.communicate()
            print(f"✗ Backend failed to start:")
            print(f"STDOUT: {stdout.decode()}")
            print(f"STDERR: {stderr.decode()}")
            return None
            
    except Exception as e:
        print(f"✗ Failed to start backend: {e}")
        return None

def start_http_server():
    """Start a simple HTTP server for the HTML dashboard"""
    print("Starting HTTP server for dashboard...")
    
    try:
        # Use Python's built-in HTTP server
        process = subprocess.Popen(
            [sys.executable, "-m", "http.server", "3000"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        
        time.sleep(2)
        
        if process.poll() is None:
            print("✓ HTTP server started successfully on port 3000")
            return process
        else:
            stdout, stderr = process.communicate()
            print(f"✗ HTTP server failed to start:")
            print(f"STDOUT: {stdout.decode()}")
            print(f"STDERR: {stderr.decode()}")
            return None
            
    except Exception as e:
        print(f"✗ Failed to start HTTP server: {e}")
        return None

def open_dashboard():
    """Open the dashboard in the browser"""
    print("Opening dashboard in browser...")
    dashboard_url = "http://localhost:3000/simple_dashboard.html"
    
    try:
        webbrowser.open(dashboard_url)
        print(f"✓ Dashboard opened at: {dashboard_url}")
    except Exception as e:
        print(f"✗ Failed to open browser: {e}")
        print(f"Please manually open: {dashboard_url}")

def main():
    """Main function"""
    print("=== Simple Network Dashboard Launcher ===")
    print("This will start:")
    print("1. Node.js backend server (port 8000)")
    print("2. HTTP server for dashboard (port 3000)")
    print("3. Open dashboard in browser")
    print()
    
    backend_process = None
    http_process = None
    
    try:
        # Start backend
        backend_process = start_nodejs_backend()
        if not backend_process:
            print("Failed to start backend. Exiting.")
            return False
        
        # Start HTTP server
        http_process = start_http_server()
        if not http_process:
            print("Failed to start HTTP server. Exiting.")
            backend_process.terminate()
            return False
        
        # Open dashboard
        open_dashboard()
        
        print("\n" + "="*50)
        print("✓ Both servers are running!")
        print("✓ Backend API: http://localhost:8000")
        print("✓ Dashboard: http://localhost:3000/simple_dashboard.html")
        print("="*50)
        print("\nPress Ctrl+C to stop all servers")
        
        # Keep running until interrupted
        while True:
            time.sleep(1)
            
            # Check if processes are still running
            if backend_process.poll() is not None:
                print("Backend server stopped unexpectedly!")
                break
                
            if http_process.poll() is not None:
                print("HTTP server stopped unexpectedly!")
                break
                
    except KeyboardInterrupt:
        print("\nShutting down servers...")
        
    finally:
        # Clean up processes
        if backend_process:
            backend_process.terminate()
            print("✓ Backend server stopped")
            
        if http_process:
            http_process.terminate()
            print("✓ HTTP server stopped")
            
        print("✓ All servers stopped")

if __name__ == "__main__":
    main()
