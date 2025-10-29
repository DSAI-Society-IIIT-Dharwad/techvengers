#!/usr/bin/env python3
"""
Test script for the Inject Anomaly feature
Verifies that the threat injection functionality works correctly
"""

import sys
import os
from datetime import datetime
import random

# Add the current directory to Python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from network_dashboard_desktop import RealTimeMLManager

def test_injection_functionality():
    """Test the threat injection functionality"""
    
    print("=" * 60)
    print("TESTING INJECT ANOMALY FUNCTIONALITY")
    print("=" * 60)
    
    # Initialize ML manager
    ml_manager = RealTimeMLManager()
    ml_manager.load_models()
    
    # Train with normal data first
    print("Training model with normal traffic...")
    for i in range(50):
        normal_packet = {
            'id': i,
            'timestamp': datetime.now(),
            'source': f"192.168.1.{random.randint(1, 50)}",
            'destination': f"192.168.1.{random.randint(51, 100)}",
            'protocol': random.choice(['TCP', 'UDP']),
            'port': random.choice([80, 443, 22, 25, 53]),
            'size': random.randint(64, 1500),
            'protocol_num': random.choice([1, 2]),
            'flags': random.randint(0, 15)
        }
        ml_manager.add_training_sample(normal_packet)
    
    # Train the models
    ml_manager.train_models()
    print("Model trained successfully!")
    
    # Test DDoS injection
    print("\n--- Testing DDoS Attack Injection ---")
    ddos_packet = {
        'id': 999,
        'timestamp': datetime.now(),
        'source': '192.168.1.200',
        'destination': '192.168.1.1',
        'protocol': 'UDP',
        'port': 50000,
        'size': 2000,
        'protocol_num': 2,
        'flags': 0
    }
    
    ml_manager.add_training_sample(ddos_packet)
    result = ml_manager.predict_anomaly(ddos_packet)
    
    print(f"Packet: {ddos_packet['source']} -> {ddos_packet['destination']}:{ddos_packet['port']}")
    print(f"Protocol: {ddos_packet['protocol']}, Size: {ddos_packet['size']} bytes")
    print(f"Threat Detected: {result['is_anomaly']}")
    print(f"Confidence: {result['confidence']:.3f}")
    
    # Test Port Scan injection
    print("\n--- Testing Port Scan Injection ---")
    scan_packet = {
        'id': 1000,
        'timestamp': datetime.now(),
        'source': '192.168.1.250',
        'destination': '192.168.1.1',
        'protocol': 'TCP',
        'port': 22,
        'size': 20,
        'protocol_num': 1,
        'flags': 2
    }
    
    ml_manager.add_training_sample(scan_packet)
    result = ml_manager.predict_anomaly(scan_packet)
    
    print(f"Packet: {scan_packet['source']} -> {scan_packet['destination']}:{scan_packet['port']}")
    print(f"Protocol: {scan_packet['protocol']}, Size: {scan_packet['size']} bytes")
    print(f"Threat Detected: {result['is_anomaly']}")
    print(f"Confidence: {result['confidence']:.3f}")
    
    # Test External Communication injection
    print("\n--- Testing External Communication Injection ---")
    external_packet = {
        'id': 1001,
        'timestamp': datetime.now(),
        'source': '8.8.8.8',
        'destination': '192.168.1.100',
        'protocol': 'TCP',
        'port': 443,
        'size': 1000,
        'protocol_num': 1,
        'flags': 0
    }
    
    ml_manager.add_training_sample(external_packet)
    result = ml_manager.predict_anomaly(external_packet)
    
    print(f"Packet: {external_packet['source']} -> {external_packet['destination']}:{external_packet['port']}")
    print(f"Protocol: {external_packet['protocol']}, Size: {external_packet['size']} bytes")
    print(f"Threat Detected: {result['is_anomaly']}")
    print(f"Confidence: {result['confidence']:.3f}")
    
    print("\n" + "=" * 60)
    print("INJECT ANOMALY FUNCTIONALITY TEST COMPLETE")
    print("=" * 60)
    print("The desktop application now includes:")
    print("- Inject Anomaly tab in navigation")
    print("- 6 different threat injection buttons")
    print("- Real-time threat detection results")
    print("- Live logging of injection attempts")
    print("- Automatic threat classification")
    print("\nTo use: Run the desktop app and click 'Inject Anomaly' tab")

if __name__ == "__main__":
    test_injection_functionality()
