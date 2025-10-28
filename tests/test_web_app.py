#!/usr/bin/env python3
"""
Simple test to verify the React web application setup
"""

import requests
import time
import webbrowser
import os

def test_api():
    """Test if API server is running"""
    try:
        response = requests.get('http://localhost:5000/api/health', timeout=5)
        if response.status_code == 200:
            print("✅ API Server is running!")
            print(f"   Response: {response.json()}")
            return True
        else:
            print(f"❌ API Server returned status {response.status_code}")
            return False
    except requests.exceptions.ConnectionError:
        print("❌ Cannot connect to API server on port 5000")
        print("   Make sure to run: python api_server.py")
        return False
    except Exception as e:
        print(f"❌ Error testing API: {e}")
        return False

def test_react():
    """Test if React app is running"""
    try:
        response = requests.get('http://localhost:3000', timeout=5)
        if response.status_code == 200:
            print("✅ React App is running!")
            print("   URL: http://localhost:3000")
            return True
        else:
            print(f"❌ React App returned status {response.status_code}")
            return False
    except requests.exceptions.ConnectionError:
        print("❌ Cannot connect to React app on port 3000")
        print("   Make sure to run: cd network-dashboard && npm start")
        return False
    except Exception as e:
        print(f"❌ Error testing React app: {e}")
        return False

def main():
    print("🧪 Testing Network Traffic Analyzer Web Application")
    print("=" * 60)
    
    # Test API server
    print("\n🔍 Testing API Server...")
    api_working = test_api()
    
    # Test React app
    print("\n🔍 Testing React App...")
    react_working = test_react()
    
    print("\n" + "=" * 60)
    print("📊 Test Results:")
    print(f"   API Server: {'✅ Working' if api_working else '❌ Not Working'}")
    print(f"   React App: {'✅ Working' if react_working else '❌ Not Working'}")
    
    if api_working and react_working:
        print("\n🎉 Both services are running!")
        print("🌐 Open your browser to: http://localhost:3000")
        
        # Try to open browser
        try:
            webbrowser.open("http://localhost:3000")
            print("🚀 Browser opened automatically!")
        except:
            print("⚠️  Could not open browser automatically")
    else:
        print("\n⚠️  Some services are not running.")
        print("\n🔧 To start manually:")
        print("   1. Terminal 1: python api_server.py")
        print("   2. Terminal 2: cd network-dashboard && npm start")
        print("   3. Open: http://localhost:3000")

if __name__ == "__main__":
    main()
