#!/usr/bin/env python3
"""
Test script for the React Web Application
Tests API endpoints and verifies data loading
"""

import requests
import json
import time
import sys
import os

API_BASE_URL = 'http://localhost:5000/api'

def test_api_endpoint(endpoint, description):
    """Test a single API endpoint"""
    try:
        response = requests.get(f"{API_BASE_URL}{endpoint}", timeout=5)
        if response.status_code == 200:
            data = response.json()
            print(f"✅ {description}")
            print(f"   Status: {response.status_code}")
            print(f"   Data keys: {list(data.keys()) if isinstance(data, dict) else 'Array'}")
            return True
        else:
            print(f"❌ {description}")
            print(f"   Status: {response.status_code}")
            return False
    except requests.exceptions.ConnectionError:
        print(f"❌ {description}")
        print("   Error: Cannot connect to API server")
        return False
    except Exception as e:
        print(f"❌ {description}")
        print(f"   Error: {e}")
        return False

def main():
    """Test all API endpoints"""
    print("🧪 Testing Network Traffic Analyzer Web API")
    print("=" * 50)
    
    # Test endpoints
    endpoints = [
        ("/health", "Health Check"),
        ("/stats", "Statistics"),
        ("/packets?limit=10", "Packets Data"),
        ("/alerts?limit=10", "Alerts Data"),
        ("/traffic-over-time", "Traffic Over Time"),
        ("/top-ips", "Top IPs"),
        ("/protocol-distribution", "Protocol Distribution"),
        ("/geographic-data", "Geographic Data")
    ]
    
    results = []
    for endpoint, description in endpoints:
        result = test_api_endpoint(endpoint, description)
        results.append(result)
        time.sleep(0.5)  # Small delay between requests
    
    print("\n" + "=" * 50)
    print(f"📊 Test Results: {sum(results)}/{len(results)} endpoints working")
    
    if all(results):
        print("🎉 All API endpoints are working correctly!")
        print("\n🌐 You can now:")
        print("   1. Start the React app: cd network-dashboard && npm start")
        print("   2. Open http://localhost:3000 in your browser")
        print("   3. The dashboard should load with real data")
    else:
        print("⚠️  Some endpoints failed. Check the API server logs.")
        print("\n🔧 Troubleshooting:")
        print("   1. Make sure the API server is running: python api_server.py")
        print("   2. Check that data files exist in the data/ directory")
        print("   3. Verify Flask and dependencies are installed")

if __name__ == "__main__":
    main()
