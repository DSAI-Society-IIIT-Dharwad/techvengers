#!/usr/bin/env python3
"""
Complete ML Dashboard Launcher
Starts ML service, Node.js backend, and HTTP server for dashboard
"""

import subprocess
import webbrowser
import time
import os
import sys
import requests
from pathlib import Path

class MLDashboardLauncher:
    def __init__(self):
        self.project_root = Path(__file__).parent
        self.ml_process = None
        self.backend_process = None
        self.http_process = None
        
    def start_ml_service(self):
        """Start the Python ML service"""
        print("Starting ML Service (Python Flask)...")
        
        try:
            self.ml_process = subprocess.Popen(
                [sys.executable, "ml_service.py"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            # Wait for ML service to start
            time.sleep(5)
            
            # Check if ML service is running
            try:
                response = requests.get("http://localhost:5000/health", timeout=5)
                if response.status_code == 200:
                    print("✓ ML Service started successfully on port 5000")
                    return True
            except:
                pass
                
            # Check process status
            if self.ml_process.poll() is None:
                print("✓ ML Service process started")
                return True
            else:
                stdout, stderr = self.ml_process.communicate()
                print(f"✗ ML Service failed to start:")
                print(f"STDOUT: {stdout}")
                print(f"STDERR: {stderr}")
                return False
                
        except Exception as e:
            print(f"✗ Failed to start ML service: {e}")
            return False
    
    def start_backend(self):
        """Start the Node.js backend"""
        print("Starting Node.js Backend...")
        
        web_app_dir = self.project_root / "web-app"
        
        try:
            # Install dependencies first
            print("Installing Node.js dependencies...")
            install_result = subprocess.run(
                ["npm", "install"],
                cwd=web_app_dir,
                capture_output=True,
                text=True
            )
            
            if install_result.returncode != 0:
                print(f"Warning: npm install had issues: {install_result.stderr}")
            
            # Start backend
            self.backend_process = subprocess.Popen(
                ["node", "server.js"],
                cwd=web_app_dir,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            # Wait for backend to start
            time.sleep(3)
            
            # Check if backend is running
            try:
                response = requests.get("http://localhost:8000/api/health", timeout=5)
                if response.status_code == 200:
                    print("✓ Node.js Backend started successfully on port 8000")
                    return True
            except:
                pass
                
            if self.backend_process.poll() is None:
                print("✓ Backend process started")
                return True
            else:
                stdout, stderr = self.backend_process.communicate()
                print(f"✗ Backend failed to start:")
                print(f"STDOUT: {stdout}")
                print(f"STDERR: {stderr}")
                return False
                
        except Exception as e:
            print(f"✗ Failed to start backend: {e}")
            return False
    
    def start_http_server(self):
        """Start HTTP server for dashboard"""
        print("Starting HTTP Server for Dashboard...")
        
        try:
            self.http_process = subprocess.Popen(
                [sys.executable, "-m", "http.server", "3000"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            time.sleep(2)
            
            # Check if HTTP server is running
            try:
                response = requests.get("http://localhost:3000/simple_dashboard.html", timeout=5)
                if response.status_code == 200:
                    print("✓ HTTP Server started successfully on port 3000")
                    return True
            except:
                pass
                
            if self.http_process.poll() is None:
                print("✓ HTTP Server process started")
                return True
            else:
                stdout, stderr = self.http_process.communicate()
                print(f"✗ HTTP Server failed to start:")
                print(f"STDOUT: {stdout}")
                print(f"STDERR: {stderr}")
                return False
                
        except Exception as e:
            print(f"✗ Failed to start HTTP server: {e}")
            return False
    
    def test_all_services(self):
        """Test all services are responding"""
        print("\nTesting all services...")
        
        services = [
            ("ML Service", "http://localhost:5000/health"),
            ("Backend API", "http://localhost:8000/api/health"),
            ("Dashboard", "http://localhost:3000/simple_dashboard.html")
        ]
        
        all_working = True
        
        for service_name, url in services:
            try:
                response = requests.get(url, timeout=5)
                if response.status_code == 200:
                    print(f"✓ {service_name}: OK")
                else:
                    print(f"✗ {service_name}: Status {response.status_code}")
                    all_working = False
            except Exception as e:
                print(f"✗ {service_name}: {e}")
                all_working = False
        
        return all_working
    
    def open_dashboard(self):
        """Open dashboard in browser"""
        print("Opening dashboard in browser...")
        dashboard_url = "http://localhost:3000/simple_dashboard.html"
        
        try:
            webbrowser.open(dashboard_url)
            print(f"✓ Dashboard opened at: {dashboard_url}")
        except Exception as e:
            print(f"✗ Failed to open browser: {e}")
            print(f"Please manually open: {dashboard_url}")
    
    def cleanup(self):
        """Stop all processes"""
        print("\nStopping all services...")
        
        processes = [
            ("ML Service", self.ml_process),
            ("Backend", self.backend_process),
            ("HTTP Server", self.http_process)
        ]
        
        for name, process in processes:
            if process:
                try:
                    process.terminate()
                    process.wait(timeout=5)
                    print(f"✓ {name} stopped")
                except subprocess.TimeoutExpired:
                    process.kill()
                    print(f"✓ {name} force stopped")
                except Exception as e:
                    print(f"✗ Error stopping {name}: {e}")
    
    def run(self):
        """Main run method"""
        print("=== ML Network Dashboard Launcher ===")
        print("Starting complete ML-powered network monitoring system...")
        print()
        
        try:
            # Start ML service
            if not self.start_ml_service():
                print("Failed to start ML service. Exiting.")
                return False
            
            # Start backend
            if not self.start_backend():
                print("Failed to start backend. Exiting.")
                self.cleanup()
                return False
            
            # Start HTTP server
            if not self.start_http_server():
                print("Failed to start HTTP server. Exiting.")
                self.cleanup()
                return False
            
            # Test all services
            if not self.test_all_services():
                print("Some services are not responding properly.")
            
            # Open dashboard
            self.open_dashboard()
            
            print("\n" + "="*60)
            print("✓ Complete ML Dashboard System is running!")
            print("✓ ML Service: http://localhost:5000")
            print("✓ Backend API: http://localhost:8000")
            print("✓ Dashboard: http://localhost:3000/simple_dashboard.html")
            print("="*60)
            print("\nPress Ctrl+C to stop all services")
            
            # Keep running until interrupted
            while True:
                time.sleep(1)
                
                # Check if any process died
                if self.ml_process and self.ml_process.poll() is not None:
                    print("ML Service stopped unexpectedly!")
                    break
                    
                if self.backend_process and self.backend_process.poll() is not None:
                    print("Backend stopped unexpectedly!")
                    break
                    
                if self.http_process and self.http_process.poll() is not None:
                    print("HTTP Server stopped unexpectedly!")
                    break
                    
        except KeyboardInterrupt:
            print("\nShutdown requested by user")
            
        finally:
            self.cleanup()
            print("✓ All services stopped")

def main():
    launcher = MLDashboardLauncher()
    launcher.run()

if __name__ == "__main__":
    main()

