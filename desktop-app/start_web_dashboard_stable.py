#!/usr/bin/env python3
"""
Stable Web Dashboard Launcher
Starts the web dashboard without debug mode to prevent auto-restarts
"""

import sys
import os

# Add current directory to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

def main():
    print("=" * 60)
    print("NETWORK SECURITY WEB DASHBOARD - STABLE MODE")
    print("=" * 60)
    print()
    print("Features:")
    print("- Real-time network packet capture from WiFi")
    print("- ML-powered anomaly detection")
    print("- Persistent data storage (no data loss on restart)")
    print("- Stable mode (no auto-restarts)")
    print("- Professional web interface")
    print("- Real-time threat analysis")
    print("- Device monitoring and tracking")
    print()
    print("Starting stable web server...")
    print("Web interface will be available at: http://localhost:5000")
    print()
    print("Press Ctrl+C to stop the server")
    print("=" * 60)
    
    try:
        # Import and run the web dashboard
        from web_dashboard import app, socketio
        
        # Run in stable mode (no debug, no auto-reload)
        socketio.run(app, debug=False, host='0.0.0.0', port=5000, use_reloader=False)
        
    except KeyboardInterrupt:
        print("\nServer stopped by user")
    except Exception as e:
        print(f"Error starting server: {e}")
        print("Make sure you have all required dependencies installed:")
        print("pip install flask flask-socketio scapy scikit-learn")

if __name__ == '__main__':
    main()
