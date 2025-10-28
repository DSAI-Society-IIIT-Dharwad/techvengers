#!/usr/bin/env python3
"""
Auto Server Launcher
Automatically starts both backend and frontend servers for the network dashboard
"""

import subprocess
import time
import sys
import os
import requests
import threading
from pathlib import Path

class ServerLauncher:
    def __init__(self):
        self.backend_process = None
        self.frontend_process = None
        self.backend_port = 8000
        self.frontend_port = 3000
        self.project_root = Path(__file__).parent
        self.web_app_dir = self.project_root / "web-app"
        self.react_app_dir = self.web_app_dir / "network-dashboard"
        
    def check_dependencies(self):
        """Check if all required dependencies are available"""
        print("Checking dependencies...")
        
        # Check Python
        try:
            python_version = subprocess.run([sys.executable, "--version"], 
                                          capture_output=True, text=True, check=True)
            print(f"✓ Python: {python_version.stdout.strip()}")
        except subprocess.CalledProcessError:
            print("✗ Python not found")
            return False
            
        # Check Node.js
        try:
            node_version = subprocess.run(["node", "--version"], 
                                       capture_output=True, text=True, check=True)
            print(f"✓ Node.js: {node_version.stdout.strip()}")
        except (subprocess.CalledProcessError, FileNotFoundError):
            print("✗ Node.js not found")
            return False
            
        # Check npm
        try:
            npm_version = subprocess.run(["npm", "--version"], 
                                      capture_output=True, text=True, check=True)
            print(f"✓ npm: {npm_version.stdout.strip()}")
        except (subprocess.CalledProcessError, FileNotFoundError):
            print("✗ npm not found")
            return False
            
        # Check if React app exists
        if not self.react_app_dir.exists():
            print("✗ React app directory not found")
            return False
        print("✓ React app directory found")
        
        # Check if package.json exists
        package_json = self.react_app_dir / "package.json"
        if not package_json.exists():
            print("✗ package.json not found")
            return False
        print("✓ package.json found")
        
        # Check if backend API server exists
        api_server = self.web_app_dir / "realtime_api_server.py"
        if not api_server.exists():
            print("✗ Backend API server not found")
            return False
        print("✓ Backend API server found")
        
        return True
    
    def install_dependencies(self):
        """Install Python and Node.js dependencies"""
        print("\nInstalling dependencies...")
        
        # Install Python dependencies
        print("Installing Python dependencies...")
        try:
            subprocess.run([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"], 
                         check=True, cwd=self.project_root)
            print("✓ Python dependencies installed")
        except subprocess.CalledProcessError as e:
            print(f"✗ Failed to install Python dependencies: {e}")
            return False
            
        # Install Node.js dependencies
        print("Installing Node.js dependencies...")
        try:
            subprocess.run(["npm", "install"], check=True, cwd=self.react_app_dir)
            print("✓ Node.js dependencies installed")
        except subprocess.CalledProcessError as e:
            print(f"✗ Failed to install Node.js dependencies: {e}")
            return False
            
        return True
    
    def start_backend(self):
        """Start the FastAPI backend server"""
        print(f"\nStarting backend server on port {self.backend_port}...")
        
        try:
            # Change to web-app directory and start the backend
            self.backend_process = subprocess.Popen(
                [sys.executable, "realtime_api_server.py"],
                cwd=self.web_app_dir,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            # Wait a moment for server to start
            time.sleep(3)
            
            # Check if server is running
            if self.backend_process.poll() is None:
                print("✓ Backend server started successfully")
                return True
            else:
                stdout, stderr = self.backend_process.communicate()
                print(f"✗ Backend server failed to start:")
                print(f"STDOUT: {stdout}")
                print(f"STDERR: {stderr}")
                return False
                
        except Exception as e:
            print(f"✗ Failed to start backend server: {e}")
            return False
    
    def start_frontend(self):
        """Start the React frontend server"""
        print(f"\nStarting frontend server on port {self.frontend_port}...")
        
        try:
            # Start React development server
            self.frontend_process = subprocess.Popen(
                ["npm", "start"],
                cwd=self.react_app_dir,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            # Wait for React to start
            time.sleep(10)
            
            # Check if server is running
            if self.frontend_process.poll() is None:
                print("✓ Frontend server started successfully")
                return True
            else:
                stdout, stderr = self.frontend_process.communicate()
                print(f"✗ Frontend server failed to start:")
                print(f"STDOUT: {stdout}")
                print(f"STDERR: {stderr}")
                return False
                
        except Exception as e:
            print(f"✗ Failed to start frontend server: {e}")
            return False
    
    def test_connections(self):
        """Test if both servers are responding"""
        print("\nTesting server connections...")
        
        # Test backend
        try:
            response = requests.get(f"http://localhost:{self.backend_port}/api/health", timeout=5)
            if response.status_code == 200:
                print("✓ Backend server is responding")
            else:
                print(f"✗ Backend server returned status {response.status_code}")
                return False
        except requests.exceptions.RequestException as e:
            print(f"✗ Backend server not responding: {e}")
            return False
            
        # Test frontend
        try:
            response = requests.get(f"http://localhost:{self.frontend_port}", timeout=5)
            if response.status_code == 200:
                print("✓ Frontend server is responding")
            else:
                print(f"✗ Frontend server returned status {response.status_code}")
                return False
        except requests.exceptions.RequestException as e:
            print(f"✗ Frontend server not responding: {e}")
            return False
            
        return True
    
    def monitor_processes(self):
        """Monitor running processes and restart if needed"""
        print("\nMonitoring servers...")
        print("Press Ctrl+C to stop all servers")
        
        try:
            while True:
                time.sleep(5)
                
                # Check backend
                if self.backend_process and self.backend_process.poll() is not None:
                    print("Backend server stopped unexpectedly, restarting...")
                    self.start_backend()
                
                # Check frontend
                if self.frontend_process and self.frontend_process.poll() is not None:
                    print("Frontend server stopped unexpectedly, restarting...")
                    self.start_frontend()
                    
        except KeyboardInterrupt:
            print("\nShutting down servers...")
            self.stop_all()
    
    def stop_all(self):
        """Stop all running processes"""
        print("\nStopping all servers...")
        
        if self.backend_process:
            self.backend_process.terminate()
            try:
                self.backend_process.wait(timeout=5)
                print("✓ Backend server stopped")
            except subprocess.TimeoutExpired:
                self.backend_process.kill()
                print("✓ Backend server force stopped")
        
        if self.frontend_process:
            self.frontend_process.terminate()
            try:
                self.frontend_process.wait(timeout=5)
                print("✓ Frontend server stopped")
            except subprocess.TimeoutExpired:
                self.frontend_process.kill()
                print("✓ Frontend server force stopped")
    
    def run(self):
        """Main run method"""
        print("=== Network Dashboard Auto Server Launcher ===")
        print(f"Project root: {self.project_root}")
        print(f"Backend port: {self.backend_port}")
        print(f"Frontend port: {self.frontend_port}")
        
        # Check dependencies
        if not self.check_dependencies():
            print("\nDependency check failed. Please install missing dependencies.")
            return False
        
        # Install dependencies
        if not self.install_dependencies():
            print("\nDependency installation failed.")
            return False
        
        # Start backend
        if not self.start_backend():
            print("\nFailed to start backend server.")
            return False
        
        # Start frontend
        if not self.start_frontend():
            print("\nFailed to start frontend server.")
            self.stop_all()
            return False
        
        # Test connections
        if not self.test_connections():
            print("\nServer connection test failed.")
            self.stop_all()
            return False
        
        # Show success message
        print("\n" + "="*50)
        print("✓ Both servers are running successfully!")
        print(f"✓ Backend API: http://localhost:{self.backend_port}")
        print(f"✓ Frontend Dashboard: http://localhost:{self.frontend_port}")
        print("="*50)
        
        # Monitor processes
        self.monitor_processes()
        
        return True

def main():
    """Main entry point"""
    launcher = ServerLauncher()
    
    try:
        success = launcher.run()
        if not success:
            sys.exit(1)
    except KeyboardInterrupt:
        print("\nShutdown requested by user")
        launcher.stop_all()
    except Exception as e:
        print(f"\nUnexpected error: {e}")
        launcher.stop_all()
        sys.exit(1)

if __name__ == "__main__":
    main()
