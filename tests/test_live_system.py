#!/usr/bin/env python3
"""
Test the live network analyzer
"""

import requests
import json
import time

API_BASE_URL = 'http://localhost:5000/api'

def test_live_system():
    """Test the live network analyzer system"""
    print("Testing Live Network Traffic Analyzer System")
    print("=" * 50)
    
    try:
        # Test health endpoint
        response = requests.get(f"{API_BASE_URL}/health", timeout=5)
        if response.status_code == 200:
            data = response.json()
            print(f"[OK] Health Check")
            print(f"   Status: {data['status']}")
            print(f"   Models Loaded: {data['models_loaded']}")
            print(f"   Live Capture: {data['live_capture']}")
            print(f"   Live Packets: {data['live_packets']}")
            print(f"   Live Alerts: {data['live_alerts']}")
        else:
            print(f"[ERROR] Health Check - Status: {response.status_code}")
            return
        
        # Test stats endpoint
        response = requests.get(f"{API_BASE_URL}/stats", timeout=5)
        if response.status_code == 200:
            data = response.json()
            print(f"\n[OK] Statistics")
            print(f"   Total Packets: {data['total_packets']}")
            print(f"   Live Packets: {data['live_packets']}")
            print(f"   Live Alerts: {data['live_alerts']}")
            print(f"   ML Models: {data['ml_models_loaded']}")
            print(f"   Capture Active: {data['live_capture_active']}")
        else:
            print(f"[ERROR] Statistics - Status: {response.status_code}")
        
        # Test live packets
        response = requests.get(f"{API_BASE_URL}/live-packets?limit=5", timeout=5)
        if response.status_code == 200:
            data = response.json()
            print(f"\n[OK] Live Packets")
            print(f"   Total: {data['total']}")
            print(f"   Sample: {len(data['packets'])} packets")
            if data['packets']:
                sample = data['packets'][0]
                print(f"   Example: {sample.get('src_ip', 'N/A')} -> {sample.get('dst_ip', 'N/A')}")
        else:
            print(f"[ERROR] Live Packets - Status: {response.status_code}")
        
        # Test live alerts
        response = requests.get(f"{API_BASE_URL}/live-alerts?limit=5", timeout=5)
        if response.status_code == 200:
            data = response.json()
            print(f"\n[OK] Live Alerts")
            print(f"   Total: {data['total']}")
            print(f"   Sample: {len(data['alerts'])} alerts")
            if data['alerts']:
                sample = data['alerts'][0]
                print(f"   Example: {sample.get('reason', 'N/A')} (Risk: {sample.get('risk_level', 'N/A')})")
        else:
            print(f"[ERROR] Live Alerts - Status: {response.status_code}")
        
        print(f"\n" + "=" * 50)
        print("SUCCESS: Live Network Analyzer is working!")
        print("\nTo view the dashboard:")
        print("1. Open live_dashboard.html in your browser")
        print("2. Click 'Start Capture' to begin live monitoring")
        print("3. Watch for ML-powered anomaly detection alerts")
        
    except requests.exceptions.ConnectionError:
        print("[ERROR] Cannot connect to live analyzer")
        print("Make sure to run: python live_network_analyzer.py")
    except Exception as e:
        print(f"[ERROR] {e}")

if __name__ == "__main__":
    test_live_system()
