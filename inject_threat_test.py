#!/usr/bin/env python3
"""
Simple Threat Injection Test
Demonstrates injecting specific threats and verifying ML detection
"""

import sys
import os
import numpy as np
from datetime import datetime
import random

# Add the current directory to Python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Import our ML manager
from network_dashboard_desktop import RealTimeMLManager

def inject_and_test_threat():
    """Inject a specific threat and test detection"""
    
    print("=" * 50)
    print("THREAT INJECTION TEST")
    print("=" * 50)
    
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
    
    # Test 1: Inject a DDoS attack
    print("\n--- TEST 1: DDoS Attack Injection ---")
    ddos_packet = {
        'id': 999,
        'timestamp': datetime.now(),
        'source': '192.168.1.200',
        'destination': '192.168.1.1',
        'protocol': 'UDP',
        'port': 50000,
        'size': 2000,  # Large packet
        'protocol_num': 2,
        'flags': 0
    }
    
    result = ml_manager.predict_anomaly(ddos_packet)
    print(f"Packet: {ddos_packet['source']} -> {ddos_packet['destination']}:{ddos_packet['port']}")
    print(f"Protocol: {ddos_packet['protocol']}, Size: {ddos_packet['size']} bytes")
    print(f"Threat Detected: {result['is_anomaly']}")
    print(f"Confidence: {result['confidence']:.3f}")
    
    # Test 2: Inject a port scan
    print("\n--- TEST 2: Port Scan Injection ---")
    scan_packet = {
        'id': 1000,
        'timestamp': datetime.now(),
        'source': '192.168.1.250',
        'destination': '192.168.1.1',
        'protocol': 'TCP',
        'port': 22,  # SSH port
        'size': 20,  # Small packet
        'protocol_num': 1,
        'flags': 2
    }
    
    result = ml_manager.predict_anomaly(scan_packet)
    print(f"Packet: {scan_packet['source']} -> {scan_packet['destination']}:{scan_packet['port']}")
    print(f"Protocol: {scan_packet['protocol']}, Size: {scan_packet['size']} bytes")
    print(f"Threat Detected: {result['is_anomaly']}")
    print(f"Confidence: {result['confidence']:.3f}")
    
    # Test 3: Inject external communication
    print("\n--- TEST 3: External Communication Injection ---")
    external_packet = {
        'id': 1001,
        'timestamp': datetime.now(),
        'source': '8.8.8.8',  # External IP
        'destination': '192.168.1.100',
        'protocol': 'TCP',
        'port': 443,
        'size': 1000,
        'protocol_num': 1,
        'flags': 0
    }
    
    result = ml_manager.predict_anomaly(external_packet)
    print(f"Packet: {external_packet['source']} -> {external_packet['destination']}:{external_packet['port']}")
    print(f"Protocol: {external_packet['protocol']}, Size: {external_packet['size']} bytes")
    print(f"Threat Detected: {result['is_anomaly']}")
    print(f"Confidence: {result['confidence']:.3f}")
    
    # Test 4: Inject massive packet
    print("\n--- TEST 4: Massive Packet Injection ---")
    massive_packet = {
        'id': 1002,
        'timestamp': datetime.now(),
        'source': '192.168.1.10',
        'destination': '192.168.1.20',
        'protocol': 'TCP',
        'port': 80,
        'size': 50000,  # Very large packet
        'protocol_num': 1,
        'flags': 0
    }
    
    result = ml_manager.predict_anomaly(massive_packet)
    print(f"Packet: {massive_packet['source']} -> {massive_packet['destination']}:{massive_packet['port']}")
    print(f"Protocol: {massive_packet['protocol']}, Size: {massive_packet['size']} bytes")
    print(f"Threat Detected: {result['is_anomaly']}")
    print(f"Confidence: {result['confidence']:.3f}")
    
    # Test 5: Normal packet (should not be flagged)
    print("\n--- TEST 5: Normal Packet (False Positive Check) ---")
    normal_packet = {
        'id': 1003,
        'timestamp': datetime.now(),
        'source': '192.168.1.5',
        'destination': '192.168.1.15',
        'protocol': 'TCP',
        'port': 80,
        'size': 512,
        'protocol_num': 1,
        'flags': 0
    }
    
    result = ml_manager.predict_anomaly(normal_packet)
    print(f"Packet: {normal_packet['source']} -> {normal_packet['destination']}:{normal_packet['port']}")
    print(f"Protocol: {normal_packet['protocol']}, Size: {normal_packet['size']} bytes")
    print(f"Threat Detected: {result['is_anomaly']}")
    print(f"Confidence: {result['confidence']:.3f}")
    
    print("\n" + "=" * 50)
    print("THREAT INJECTION TEST COMPLETE")
    print("=" * 50)

if __name__ == "__main__":
    inject_and_test_threat()
