#!/usr/bin/env python3
"""
Startup script for Network Traffic Analyzer Web Application
Runs both the Flask API server and React development server
"""

import subprocess
import sys
import os
import time
import threading
import webbrowser
from pathlib import Path

def run_api_server():
    """Run the Flask API server"""
    print("🚀 Starting Flask API Server...")
    api_script = Path(__file__).parent / "api_server.py"
    try:
        subprocess.run([sys.executable, str(api_script)], check=True)
    except KeyboardInterrupt:
        print("\n🛑 API Server stopped")
    except Exception as e:
        print(f"❌ Error running API server: {e}")

def run_react_app():
    """Run the React development server"""
    print("🚀 Starting React Development Server...")
    react_dir = Path(__file__).parent / "network-dashboard"
    try:
        subprocess.run(["npm", "start"], cwd=react_dir, check=True)
    except KeyboardInterrupt:
        print("\n🛑 React App stopped")
    except Exception as e:
        print(f"❌ Error running React app: {e}")

def check_dependencies():
    """Check if required dependencies are installed"""
    print("🔍 Checking dependencies...")
    
    # Check Python packages
    try:
        import flask
        import flask_cors
        import pandas
        print("✅ Python dependencies installed")
    except ImportError as e:
        print(f"❌ Missing Python dependency: {e}")
        print("Run: pip install flask flask-cors pandas")
        return False
    
    # Check Node.js packages
    react_dir = Path(__file__).parent / "network-dashboard"
    if not (react_dir / "node_modules").exists():
        print("❌ Node.js dependencies not installed")
        print("Run: cd network-dashboard && npm install")
        return False
    else:
        print("✅ Node.js dependencies installed")
    
    return True

def main():
    """Main function to start both servers"""
    print("=" * 60)
    print("🛡️  Network Traffic Analyzer Web Application")
    print("=" * 60)
    
    if not check_dependencies():
        print("\n❌ Please install missing dependencies and try again")
        return
    
    print("\n📋 Starting services:")
    print("   • Flask API Server: http://localhost:5000")
    print("   • React App: http://localhost:3000")
    print("\n⏳ Starting servers... (Press Ctrl+C to stop)")
    
    # Start API server in a separate thread
    api_thread = threading.Thread(target=run_api_server, daemon=True)
    api_thread.start()
    
    # Wait a moment for API server to start
    time.sleep(3)
    
    # Open browser after a delay
    def open_browser():
        time.sleep(5)
        try:
            webbrowser.open("http://localhost:3000")
            print("🌐 Opened browser to http://localhost:3000")
        except:
            print("⚠️  Could not open browser automatically")
    
    browser_thread = threading.Thread(target=open_browser, daemon=True)
    browser_thread.start()
    
    # Start React app in main thread
    try:
        run_react_app()
    except KeyboardInterrupt:
        print("\n🛑 Shutting down...")
        print("✅ All services stopped")

if __name__ == "__main__":
    main()
