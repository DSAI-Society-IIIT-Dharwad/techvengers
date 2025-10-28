#!/usr/bin/env python3
"""
Test script to demonstrate model loading and usage
"""

import os
import joblib
import json
import numpy as np
import sys
sys.path.append('src')
from analyzer import NetworkTrafficAnalyzer

def test_saved_models():
    """Test loading and using the saved models."""
    print("Testing Saved Models")
    print("=" * 50)
    
    # Check if models exist
    models_dir = "data/trained_models"
    if not os.path.exists(models_dir):
        print("ERROR: No trained models directory found!")
        return
    
    # List available models
    model_files = [f for f in os.listdir(models_dir) if f.endswith('.joblib')]
    print(f"Found {len(model_files)} model files:")
    for model_file in sorted(model_files):
        print(f"   - {model_file}")
    
    # Load metadata
    metadata_files = [f for f in os.listdir(models_dir) if f.endswith('.json')]
    if metadata_files:
        metadata_file = metadata_files[0]
        with open(os.path.join(models_dir, metadata_file), 'r') as f:
            metadata = json.load(f)
        
        print(f"\nModel Training Information:")
        print(f"   Timestamp: {metadata['timestamp']}")
        print(f"   Models trained: {', '.join(metadata['models_trained'])}")
        print(f"   Training data shape: {metadata['training_data_shape']}")
        print(f"   Feature columns: {len(metadata['feature_columns'])}")
    
    # Test model loading
    print(f"\nTesting Model Loading:")
    analyzer = NetworkTrafficAnalyzer('packets_extended.csv')
    
    # Load the saved models
    if analyzer.load_models():
        print("SUCCESS: Models loaded successfully!")
        
        # Test with sample data
        print(f"\nTesting Model Predictions:")
        
        # Create sample feature vector (matching the training features)
        sample_features = {
            'packet_count': 50,
            'avg_packet_size': 64.0,
            'max_packet_size': 64.0,
            'std_packet_size': 0.0,
            'unique_destinations': 25,
            'unique_dest_ports': 5,
            'avg_time_between_packets': 0.1,
            'total_bytes': 3200,
            'protocol_diversity': 1,
            'duration_seconds': 5.0,
            'tcp_packets': 50,
            'udp_packets': 0,
            'icmp_packets': 0,
            'common_port_connections': 40,
            'high_port_connections': 10,
            'packets_per_second': 10.0,
            'bytes_per_second': 640.0
        }
        
        # Convert to numpy array
        feature_vector = np.array([sample_features[col] for col in metadata['feature_columns']]).reshape(1, -1)
        
        # Scale the features
        X_scaled = analyzer.scalers['standard'].transform(feature_vector)
        
        # Test each model
        for model_name, model in analyzer.models.items():
            try:
                if model_name == 'local_outlier_factor':
                    prediction = model.fit_predict(X_scaled)
                    score = model.negative_outlier_factor_
                else:
                    prediction = model.predict(X_scaled)
                    score = model.decision_function(X_scaled)
                
                anomaly_status = "ANOMALY" if prediction[0] == -1 else "NORMAL"
                print(f"   {model_name}: {anomaly_status} (score: {score[0]:.3f})")
                
            except Exception as e:
                print(f"   {model_name}: ERROR - {e}")
        
        print(f"\nModel files saved in: {os.path.abspath(models_dir)}")
        print(f"Total size: {sum(os.path.getsize(os.path.join(models_dir, f)) for f in os.listdir(models_dir))} bytes")
        
    else:
        print("ERROR: Failed to load models!")

if __name__ == "__main__":
    test_saved_models()
