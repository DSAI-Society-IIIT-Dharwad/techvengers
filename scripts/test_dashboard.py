#!/usr/bin/env python3
"""
Dashboard Test Script
====================

Test script to verify the dashboard components work correctly.
"""

import os
import sys
import pandas as pd
from datetime import datetime, timedelta
import numpy as np

# Add src to path
sys.path.append('src')

def test_data_files():
    """Test that required data files exist."""
    print("Testing data files...")
    
    required_files = [
        'data/packets_extended.csv',
        'data/alerts.csv',
        'data/streaming_alerts.csv'
    ]
    
    for file_path in required_files:
        if os.path.exists(file_path):
            size = os.path.getsize(file_path)
            print(f"  [OK] {file_path} ({size} bytes)")
        else:
            print(f"  [MISSING] {file_path}")
    
    print()

def test_dashboard_imports():
    """Test that dashboard can be imported."""
    print("Testing dashboard imports...")
    
    try:
        import streamlit as st
        print("  [OK] Streamlit imported successfully")
    except ImportError as e:
        print(f"  [ERROR] Streamlit import failed: {e}")
        return False
    
    try:
        import plotly.express as px
        import plotly.graph_objects as go
        print("  [OK] Plotly imported successfully")
    except ImportError as e:
        print(f"  [ERROR] Plotly import failed: {e}")
        return False
    
    try:
        import requests
        print("  [OK] Requests imported successfully")
    except ImportError as e:
        print(f"  [ERROR] Requests import failed: {e}")
        return False
    
    print()
    return True

def test_data_loading():
    """Test data loading functionality."""
    print("Testing data loading...")
    
    try:
        # Test packet data loading
        if os.path.exists('data/packets_extended.csv'):
            df = pd.read_csv('data/packets_extended.csv')
            df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')
            print(f"  [OK] Loaded {len(df)} packet records")
        else:
            print("  [MISSING] No packet data found")
        
        # Test alerts data loading
        alerts_dfs = []
        if os.path.exists('data/alerts.csv'):
            alerts_df = pd.read_csv('data/alerts.csv')
            alerts_df['timestamp'] = pd.to_datetime(alerts_df['timestamp'], errors='coerce')
            alerts_dfs.append(alerts_df)
            print(f"  [OK] Loaded {len(alerts_df)} alert records")
        
        if os.path.exists('data/streaming_alerts.csv'):
            streaming_df = pd.read_csv('data/streaming_alerts.csv')
            streaming_df['timestamp'] = pd.to_datetime(streaming_df['timestamp'], errors='coerce')
            alerts_dfs.append(streaming_df)
            print(f"  [OK] Loaded {len(streaming_df)} streaming alert records")
        
        if alerts_dfs:
            combined_df = pd.concat(alerts_dfs, ignore_index=True)
            print(f"  [OK] Combined alerts: {len(combined_df)} total records")
        
    except Exception as e:
        print(f"  [ERROR] Data loading failed: {e}")
        return False
    
    print()
    return True

def test_dashboard_class():
    """Test dashboard class instantiation."""
    print("Testing dashboard class...")
    
    try:
        from enhanced_dashboard import EnhancedNetworkDashboard
        dashboard = EnhancedNetworkDashboard()
        print("  [OK] EnhancedNetworkDashboard instantiated successfully")
        
        # Test basic methods
        packets_df = dashboard.load_packet_data()
        alerts_df = dashboard.load_alerts_data()
        metrics = dashboard.calculate_enhanced_metrics(packets_df, alerts_df)
        
        print(f"  [OK] Loaded {len(packets_df)} packets, {len(alerts_df)} alerts")
        print(f"  [OK] Calculated metrics: {metrics['total_packets']} packets, {metrics['active_alerts']} alerts")
        
    except Exception as e:
        print(f"  [ERROR] Dashboard class test failed: {e}")
        return False
    
    print()
    return True

def create_sample_data():
    """Create sample data if none exists."""
    print("Creating sample data...")
    
    # Create sample packet data
    if not os.path.exists('data/packets_extended.csv'):
        sample_packets = []
        base_time = datetime.now() - timedelta(hours=1)
        
        for i in range(100):
            packet = {
                'timestamp': base_time + timedelta(minutes=i),
                'source_ip': f'192.168.1.{i % 10 + 1}',
                'destination_ip': f'8.8.8.{i % 5 + 1}',
                'protocol': np.random.choice(['TCP', 'UDP', 'ICMP']),
                'packet_length': np.random.randint(64, 1500),
                'source_port': np.random.randint(1024, 65535),
                'destination_port': np.random.choice([80, 443, 53, 22]),
                'src_mac': f'00:1a:2b:3c:4d:{i:02x}',
                'dst_mac': f'00:5e:6f:7g:8h:{i:02x}',
                'packet_id': i,
                'method': 'Sample'
            }
            sample_packets.append(packet)
        
        df = pd.DataFrame(sample_packets)
        df.to_csv('data/packets_extended.csv', index=False)
        print(f"  [OK] Created sample packet data: {len(df)} records")
    
    # Create sample alerts data
    if not os.path.exists('data/alerts.csv'):
        sample_alerts = []
        base_time = datetime.now() - timedelta(hours=1)
        
        for i in range(5):
            alert = {
                'timestamp': base_time + timedelta(minutes=i*10),
                'alert_type': np.random.choice(['ML_ANOMALY', 'RULE_BASED']),
                'risk_level': np.random.choice(['LOW', 'MEDIUM', 'HIGH']),
                'source_ip': f'192.168.1.{i % 5 + 1}',
                'destination_ip': f'8.8.8.{i % 3 + 1}',
                'reason': f'Sample alert {i+1}',
                'anomaly_score': np.random.uniform(0.1, 2.0),
                'details': f'Sample details for alert {i+1}'
            }
            sample_alerts.append(alert)
        
        df = pd.DataFrame(sample_alerts)
        df.to_csv('data/alerts.csv', index=False)
        print(f"  [OK] Created sample alerts data: {len(df)} records")
    
    print()

def main():
    """Main test function."""
    print("Dashboard Test Suite")
    print("=" * 30)
    
    # Test data files
    test_data_files()
    
    # Test imports
    if not test_dashboard_imports():
        print("[ERROR] Import tests failed. Install missing dependencies:")
        print("   pip install streamlit plotly requests")
        return
    
    # Test data loading
    if not test_data_loading():
        print("[ERROR] Data loading tests failed.")
        return
    
    # Create sample data if needed
    create_sample_data()
    
    # Test dashboard class
    if not test_dashboard_class():
        print("[ERROR] Dashboard class tests failed.")
        return
    
    print("[SUCCESS] All tests passed!")
    print("\nTo run the dashboard:")
    print("   python scripts/dashboard_launcher.py")
    print("   or")
    print("   streamlit run src/enhanced_dashboard.py")

if __name__ == "__main__":
    main()
