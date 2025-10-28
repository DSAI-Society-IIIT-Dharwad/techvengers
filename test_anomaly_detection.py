#!/usr/bin/env python3
"""
Anomaly Detection Test Script
Tests the ML model's ability to detect various types of network anomalies and threats
"""

import sys
import os
import numpy as np
import pandas as pd
from datetime import datetime
import random
import time

# Add the current directory to Python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Import our ML manager
from network_dashboard_desktop import RealTimeMLManager

class AnomalyTester:
    """Test class for injecting and detecting network anomalies"""
    
    def __init__(self):
        self.ml_manager = RealTimeMLManager()
        self.test_results = []
        
    def generate_normal_packet(self):
        """Generate a normal network packet"""
        return {
            'id': random.randint(1, 1000),
            'timestamp': datetime.now(),
            'source': f"192.168.1.{random.randint(1, 50)}",
            'destination': f"192.168.1.{random.randint(51, 100)}",
            'protocol': random.choice(['TCP', 'UDP']),
            'port': random.choice([80, 443, 22, 25, 53, 110]),
            'size': random.randint(64, 1500),
            'protocol_num': random.choice([1, 2]),
            'flags': random.randint(0, 15)
        }
    
    def generate_anomalous_packet(self, anomaly_type):
        """Generate different types of anomalous packets"""
        base_packet = self.generate_normal_packet()
        
        if anomaly_type == "massive_size":
            # Extremely large packet
            base_packet['size'] = random.randint(10000, 65000)
            base_packet['protocol'] = 'TCP'
            
        elif anomaly_type == "suspicious_port":
            # Suspicious port scanning
            base_packet['port'] = random.randint(1, 1023)  # Well-known ports
            base_packet['source'] = f"10.0.0.{random.randint(1, 10)}"  # External IP
            
        elif anomaly_type == "unusual_protocol":
            # Unusual protocol combination
            base_packet['protocol'] = 'ICMP'
            base_packet['port'] = 0
            base_packet['size'] = random.randint(32, 64)
            
        elif anomaly_type == "external_communication":
            # External IP communication
            base_packet['source'] = f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}"
            base_packet['destination'] = f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}"
            
        elif anomaly_type == "port_scan":
            # Port scanning pattern
            base_packet['port'] = random.randint(1, 1000)
            base_packet['source'] = f"192.168.1.{random.randint(200, 254)}"
            base_packet['size'] = random.randint(20, 40)  # Small packets
            
        elif anomaly_type == "ddos_pattern":
            # DDoS-like pattern
            base_packet['size'] = random.randint(1500, 2000)
            base_packet['protocol'] = 'UDP'
            base_packet['port'] = random.randint(49152, 65535)
            
        elif anomaly_type == "malicious_payload":
            # Suspicious payload size
            base_packet['size'] = random.randint(2000, 5000)
            base_packet['protocol'] = 'TCP'
            base_packet['port'] = random.randint(1024, 49151)
            
        return base_packet
    
    def train_model_with_normal_data(self, num_samples=100):
        """Train the model with normal network traffic"""
        print(f"Training ML model with {num_samples} normal packets...")
        
        for i in range(num_samples):
            packet = self.generate_normal_packet()
            self.ml_manager.add_training_sample(packet)
            
            if i % 20 == 0:
                print(f"  Added {i+1}/{num_samples} normal packets")
        
        # Train the models
        success = self.ml_manager.train_models()
        if success:
            print("Model training completed successfully")
        else:
            print("Model training failed")
        
        return success
    
    def test_anomaly_detection(self, anomaly_type, num_tests=10):
        """Test anomaly detection for a specific type"""
        print(f"\n--- Testing {anomaly_type.upper()} Detection ---")
        
        detected_count = 0
        total_confidence = 0
        
        for i in range(num_tests):
            # Generate anomalous packet
            anomalous_packet = self.generate_anomalous_packet(anomaly_type)
            
            # Get prediction
            result = self.ml_manager.predict_anomaly(anomalous_packet)
            
            if result['is_anomaly']:
                detected_count += 1
                total_confidence += result['confidence']
                
                print(f"  Test {i+1}: DETECTED (confidence: {result['confidence']:.3f})")
                print(f"    Packet: {anomalous_packet['source']} -> {anomalous_packet['destination']}:{anomalous_packet['port']} ({anomalous_packet['protocol']}, {anomalous_packet['size']} bytes)")
            else:
                print(f"  Test {i+1}: NOT DETECTED (confidence: {result['confidence']:.3f})")
        
        detection_rate = (detected_count / num_tests) * 100
        avg_confidence = total_confidence / max(detected_count, 1)
        
        print(f"\n  Detection Rate: {detection_rate:.1f}% ({detected_count}/{num_tests})")
        print(f"  Average Confidence: {avg_confidence:.3f}")
        
        # Store results
        self.test_results.append({
            'anomaly_type': anomaly_type,
            'detection_rate': detection_rate,
            'detected_count': detected_count,
            'total_tests': num_tests,
            'avg_confidence': avg_confidence
        })
        
        return detection_rate
    
    def test_normal_traffic(self, num_tests=20):
        """Test that normal traffic is not flagged as anomalous"""
        print(f"\n--- Testing NORMAL Traffic (False Positive Check) ---")
        
        false_positives = 0
        total_confidence = 0
        
        for i in range(num_tests):
            # Generate normal packet
            normal_packet = self.generate_normal_packet()
            
            # Get prediction
            result = self.ml_manager.predict_anomaly(normal_packet)
            
            if result['is_anomaly']:
                false_positives += 1
                print(f"  Test {i+1}: FALSE POSITIVE (confidence: {result['confidence']:.3f})")
            else:
                print(f"  Test {i+1}: Normal (confidence: {result['confidence']:.3f})")
            
            total_confidence += result['confidence']
        
        false_positive_rate = (false_positives / num_tests) * 100
        avg_confidence = total_confidence / num_tests
        
        print(f"\n  False Positive Rate: {false_positive_rate:.1f}% ({false_positives}/{num_tests})")
        print(f"  Average Confidence: {avg_confidence:.3f}")
        
        return false_positive_rate
    
    def run_comprehensive_test(self):
        """Run comprehensive anomaly detection tests"""
        print("=" * 60)
        print("NETWORK ANOMALY DETECTION TEST SUITE")
        print("=" * 60)
        
        # Initialize ML manager
        print("Initializing ML Manager...")
        self.ml_manager.load_models()
        
        # Train with normal data
        if not self.train_model_with_normal_data(100):
            print("Failed to train model. Exiting.")
            return
        
        # Test different anomaly types
        anomaly_types = [
            "massive_size",
            "suspicious_port", 
            "unusual_protocol",
            "external_communication",
            "port_scan",
            "ddos_pattern",
            "malicious_payload"
        ]
        
        print(f"\nTesting {len(anomaly_types)} different anomaly types...")
        
        for anomaly_type in anomaly_types:
            self.test_anomaly_detection(anomaly_type, 15)
        
        # Test normal traffic
        self.test_normal_traffic(25)
        
        # Print summary
        self.print_summary()
    
    def print_summary(self):
        """Print test summary"""
        print("\n" + "=" * 60)
        print("TEST SUMMARY")
        print("=" * 60)
        
        print(f"{'Anomaly Type':<20} {'Detection Rate':<15} {'Tests':<10} {'Avg Confidence':<15}")
        print("-" * 60)
        
        total_detection_rate = 0
        total_tests = 0
        
        for result in self.test_results:
            print(f"{result['anomaly_type']:<20} {result['detection_rate']:<15.1f}% {result['detected_count']}/{result['total_tests']:<8} {result['avg_confidence']:<15.3f}")
            total_detection_rate += result['detection_rate']
            total_tests += 1
        
        if total_tests > 0:
            avg_detection_rate = total_detection_rate / total_tests
            print("-" * 60)
            print(f"{'OVERALL AVERAGE':<20} {avg_detection_rate:<15.1f}%")
        
        # Model status
        status = self.ml_manager.get_training_status()
        print(f"\nModel Status:")
        print(f"  Trained: {status['is_trained']}")
        print(f"  Training Samples: {status['training_samples']}")
        print(f"  Models Available: {', '.join(status['models_available'])}")
        
        print("\n" + "=" * 60)

def main():
    """Main test function"""
    try:
        tester = AnomalyTester()
        tester.run_comprehensive_test()
        
    except Exception as e:
        print(f"Error during testing: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()
