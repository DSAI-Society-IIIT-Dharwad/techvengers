#!/usr/bin/env python3
"""
Test script for the complete Network Traffic Analyzer system
"""

import requests
import json
import time

API_BASE_URL = 'http://localhost:5000/api'

def test_endpoint(endpoint, description):
    """Test a single API endpoint"""
    try:
        response = requests.get(f"{API_BASE_URL}{endpoint}", timeout=5)
        if response.status_code == 200:
            data = response.json()
            print(f"[OK] {description}")
            print(f"   Status: {response.status_code}")
            if isinstance(data, dict):
                print(f"   Keys: {list(data.keys())}")
                if 'total_packets' in data:
                    print(f"   Packets: {data['total_packets']}")
                if 'models_loaded' in data:
                    print(f"   ML Models: {data['models_loaded']}")
            return True
        else:
            print(f"[ERROR] {description}")
            print(f"   Status: {response.status_code}")
            return False
    except requests.exceptions.ConnectionError:
        print(f"[ERROR] {description}")
        print("   Error: Cannot connect to API server")
        return False
    except Exception as e:
        print(f"[ERROR] {description}")
        print(f"   Error: {e}")
        return False

def main():
    print("Testing Complete Network Traffic Analyzer System")
    print("=" * 60)
    
    # Test endpoints
    endpoints = [
        ("/health", "Health Check"),
        ("/stats", "Statistics"),
        ("/ml-status", "ML Models Status"),
        ("/packets?limit=5", "Packets Data"),
        ("/alerts?limit=5", "Alerts Data"),
        ("/protocol-distribution", "Protocol Distribution"),
        ("/top-ips", "Top IPs"),
        ("/traffic-over-time", "Traffic Over Time")
    ]
    
    results = []
    for endpoint, description in endpoints:
        result = test_endpoint(endpoint, description)
        results.append(result)
        time.sleep(0.5)
    
    print("\n" + "=" * 60)
    print(f"Test Results: {sum(results)}/{len(results)} endpoints working")
    
    if all(results):
        print("SUCCESS: Complete system is working perfectly!")
        print("\nAccess your dashboard:")
        print("   - Open complete_dashboard.html in your browser")
        print("   - API Server: http://localhost:5000")
        print("\nFeatures available:")
        print("   - Real-time packet analysis")
        print("   - ML-powered anomaly detection")
        print("   - Interactive charts and visualizations")
        print("   - Alert management system")
    else:
        print("WARNING: Some endpoints failed. Check the API server logs.")
        print("\nTroubleshooting:")
        print("   1. Make sure the API server is running: python complete_api_server.py")
        print("   2. Check that data files exist in the data/ directory")
        print("   3. Verify ML models are in data/trained_models/")

if __name__ == "__main__":
    main()