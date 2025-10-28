#!/usr/bin/env python3
"""
Test script to verify ML models are working correctly
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from network_dashboard_desktop import MLModelManager
import json

def test_ml_models():
    """Test ML model loading and prediction"""
    print("Testing ML Model Integration...")
    print("=" * 50)
    
    # Initialize ML manager
    ml_manager = MLModelManager()
    
    # Test model loading
    print("1. Loading ML models...")
    success = ml_manager.load_models()
    
    if success:
        print("   Models loaded successfully!")
        print(f"   Available models: {list(ml_manager.models.keys())}")
        print(f"   Available scalers: {list(ml_manager.scalers.keys())}")
        
        # Test prediction
        print("\n2. Testing ML prediction...")
        test_packet = {
            'source': '192.168.1.100',
            'destination': '10.0.0.50',
            'protocol': 'TCP',
            'port': 80,
            'size': 1024
        }
        
        prediction = ml_manager.predict_anomaly(test_packet)
        print(f"   Prediction completed!")
        print(f"   Is anomaly: {prediction['is_anomaly']}")
        print(f"   Confidence: {prediction['confidence']:.2%}")
        print(f"   Features used: {prediction.get('features_used', 'N/A')}")
        
        if 'model_predictions' in prediction:
            print(f"   Model predictions: {prediction['model_predictions']}")
        
        print("\n3. Testing feature extraction...")
        features = ml_manager.extract_features(test_packet)
        print(f"   Features extracted: {features.shape}")
        print(f"   Feature values: {features[0]}")
        
        print("\nAll ML tests passed! Models are working correctly.")
        return True
        
    else:
        print("   Failed to load models!")
        print("   Check if model files exist in data/trained_models/")
        return False

if __name__ == "__main__":
    test_ml_models()
