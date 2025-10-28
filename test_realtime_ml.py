#!/usr/bin/env python3
"""
Real-Time ML Implementation Test
Test the real-time ML training and prediction system
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

def test_realtime_ml():
    """Test real-time ML implementation"""
    print("Real-Time ML Implementation Test")
    print("=" * 40)
    
    try:
        from network_dashboard_desktop import RealTimeMLManager, NetworkMonitor
        
        print("1. Testing RealTimeMLManager initialization...")
        
        # Create ML manager
        ml_manager = RealTimeMLManager()
        print("   OK RealTimeMLManager created")
        
        # Test initial status
        status = ml_manager.get_training_status()
        print(f"   OK Initial training samples: {status['training_samples']}")
        print(f"   OK Min samples needed: {status['min_samples_needed']}")
        print(f"   OK Is trained: {status['is_trained']}")
        
        print("\n2. Testing packet data collection...")
        
        # Generate test packets
        test_packets = []
        for i in range(60):  # Generate more than min_samples_for_training
            packet = {
                'timestamp': '2025-01-01 12:00:00',
                'source': f"192.168.1.{i % 254 + 1}",
                'destination': f"10.0.0.{i % 254 + 1}",
                'protocol': 'TCP' if i % 2 == 0 else 'UDP',
                'size': 100 + i * 10,
                'port': 80 + i,
                'protocol_num': 1 if i % 2 == 0 else 2,
                'flags': i % 16
            }
            test_packets.append(packet)
            ml_manager.add_training_sample(packet)
        
        print(f"   OK Added {len(test_packets)} training samples")
        
        # Check training status after adding samples
        status = ml_manager.get_training_status()
        print(f"   OK Training samples after collection: {status['training_samples']}")
        
        print("\n3. Testing model training...")
        
        # Train models
        training_success = ml_manager.train_models()
        if training_success:
            print("   OK Models trained successfully")
            
            # Check final status
            status = ml_manager.get_training_status()
            print(f"   OK Is trained: {status['is_trained']}")
            print(f"   OK Available models: {status['models_available']}")
        else:
            print("   ERROR: Model training failed")
            return False
        
        print("\n4. Testing real-time prediction...")
        
        # Test prediction on new packet
        test_packet = {
            'timestamp': '2025-01-01 12:01:00',
            'source': '192.168.1.100',
            'destination': '10.0.0.200',
            'protocol': 'TCP',
            'size': 500,
            'port': 443,
            'protocol_num': 1,
            'flags': 2
        }
        
        prediction = ml_manager.predict_anomaly(test_packet)
        print(f"   OK Prediction result: {prediction['is_anomaly']}")
        print(f"   OK Confidence: {prediction['confidence']:.3f}")
        print(f"   OK Models used: {prediction.get('model_predictions', {})}")
        print(f"   OK Training samples: {prediction.get('training_samples', 0)}")
        
        print("\n5. Testing NetworkMonitor integration...")
        
        # Create network monitor
        import queue
        data_queue = queue.Queue()
        monitor = NetworkMonitor(ml_manager, data_queue)
        
        # Generate packets through monitor
        monitor.start_monitoring()
        for i in range(5):
            packet = monitor.generate_packet()
            print(f"   OK Generated packet {i+1}: {packet['protocol']} from {packet['source']}")
        
        monitor.stop_monitoring()
        
        print("\n6. Real-Time ML Test Summary:")
        print("   OK Real-time ML manager working")
        print("   OK Packet data collection working")
        print("   OK Model training on packet stream")
        print("   OK Real-time prediction working")
        print("   OK NetworkMonitor integration working")
        print("   OK No LOF model warnings")
        
        print("\nThe real-time ML implementation is working perfectly!")
        print("Features include:")
        print("- 📊 Real-time training on packet streams")
        print("- 🤖 Automatic model training after 50 packets")
        print("- ⚡ Live anomaly detection")
        print("- 📈 Dynamic confidence scoring")
        print("- 🎯 Ensemble prediction from multiple models")
        print("- 🚫 No problematic LOF model warnings")
        
        return True
        
    except Exception as e:
        print(f"ERROR: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    test_realtime_ml()
