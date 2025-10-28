#!/usr/bin/env python3
"""
ML Model Service
Python service that loads ML models and provides predictions via HTTP API
"""

import json
import joblib
import numpy as np
import pandas as pd
from datetime import datetime
import sys
import os
from pathlib import Path
from flask import Flask, request, jsonify
from flask_cors import CORS

class MLModelService:
    def __init__(self):
        self.models = {}
        self.scalers = {}
        self.metadata = {}
        self.model_dir = Path(__file__).parent / "data" / "trained_models"
        
    def load_models(self):
        """Load all trained ML models"""
        print("Loading ML models...")
        
        try:
            # Load streaming models (preferred for real-time)
            streaming_models = [
                'streaming_isolation_forest_20251029_005536.joblib',
                'streaming_local_outlier_factor_20251029_005536.joblib', 
                'streaming_one_class_svm_20251029_005536.joblib',
                'streaming_standard_scaler_20251029_005536.joblib',
                'streaming_model_metadata_20251029_005536.json'
            ]
            
            # Load models
            for model_file in streaming_models:
                if model_file.endswith('.joblib'):
                    model_name = model_file.replace('streaming_', '').replace('_20251029_005536.joblib', '')
                    model_path = self.model_dir / model_file
                    
                    if model_path.exists():
                        self.models[model_name] = joblib.load(model_path)
                        print(f"Loaded {model_name} model")
                    else:
                        print(f"Model file not found: {model_file}")
                        
                elif model_file.endswith('.json'):
                    metadata_path = self.model_dir / model_file
                    if metadata_path.exists():
                        with open(metadata_path, 'r') as f:
                            self.metadata = json.load(f)
                        print("Loaded model metadata")
                        
            # Load scaler
            scaler_path = self.model_dir / 'streaming_standard_scaler_20251029_005536.joblib'
            if scaler_path.exists():
                self.scalers['standard'] = joblib.load(scaler_path)
                print("Loaded standard scaler")
                
            print(f"Successfully loaded {len(self.models)} models")
            return True
            
        except Exception as e:
            print(f"Error loading models: {e}")
            return False
    
    def extract_features(self, packet_data):
        """Extract features from packet data for ML prediction"""
        try:
            features = []
            
            # Basic packet features
            features.append(packet_data.get('size', 0))
            features.append(packet_data.get('port', 0))
            
            # Protocol encoding
            protocol_map = {'TCP': 1, 'UDP': 2, 'ICMP': 3, 'HTTP': 4, 'HTTPS': 5}
            protocol = packet_data.get('protocol', 'TCP')
            features.append(protocol_map.get(protocol, 1))
            
            # IP type (simplified)
            source_ip = packet_data.get('source', '192.168.1.1')
            dest_ip = packet_data.get('destination', '192.168.1.1')
            
            # Check if internal IPs
            source_internal = 1 if source_ip.startswith(('192.168.', '10.', '172.')) else 0
            dest_internal = 1 if dest_ip.startswith(('192.168.', '10.', '172.')) else 0
            features.extend([source_internal, dest_internal])
            
            # Port-based features
            port = packet_data.get('port', 0)
            features.extend([
                1 if port < 1024 else 0,  # Well-known ports
                1 if 1024 <= port < 49152 else 0,  # Registered ports
                1 if port >= 49152 else 0  # Dynamic ports
            ])
            
            # Packet size categories
            size = packet_data.get('size', 0)
            features.extend([
                1 if size < 64 else 0,  # Small packets
                1 if 64 <= size < 512 else 0,  # Medium packets
                1 if size >= 512 else 0  # Large packets
            ])
            
            # Time-based features (simplified)
            now = datetime.now()
            features.extend([
                now.hour,
                now.minute,
                now.second % 10  # Simplified time pattern
            ])
            
            # Ensure we have exactly 12 features (adjust based on your model)
            while len(features) < 12:
                features.append(0)
                
            return np.array(features[:12]).reshape(1, -1)
            
        except Exception as e:
            print(f"Error extracting features: {e}")
            return np.zeros((1, 12))
    
    def predict_anomaly(self, packet_data):
        """Predict if packet is anomalous using loaded models"""
        try:
            if not self.models:
                return {'is_anomaly': False, 'confidence': 0.5, 'model': 'none'}
            
            # Extract features
            features = self.extract_features(packet_data)
            
            # Scale features
            if 'standard' in self.scalers:
                features_scaled = self.scalers['standard'].transform(features)
            else:
                features_scaled = features
            
            predictions = {}
            confidences = {}
            
            # Get predictions from all models
            for model_name, model in self.models.items():
                try:
                    if hasattr(model, 'decision_function'):
                        # For One-Class SVM
                        score = model.decision_function(features_scaled)[0]
                        prediction = score < 0
                        confidence = abs(score)
                    elif hasattr(model, 'score_samples'):
                        # For Isolation Forest
                        score = model.score_samples(features_scaled)[0]
                        prediction = score < -0.1  # Threshold for anomaly
                        confidence = abs(score)
                    else:
                        # For Local Outlier Factor
                        prediction = model.predict(features_scaled)[0] == -1
                        confidence = 0.8 if prediction else 0.2
                    
                    predictions[model_name] = prediction
                    confidences[model_name] = confidence
                    
                except Exception as e:
                    print(f"Error with {model_name}: {e}")
                    predictions[model_name] = False
                    confidences[model_name] = 0.5
            
            # Ensemble prediction (majority vote)
            anomaly_votes = sum(predictions.values())
            is_anomaly = anomaly_votes > len(predictions) / 2
            
            # Average confidence
            avg_confidence = np.mean(list(confidences.values()))
            
            return {
                'is_anomaly': bool(is_anomaly),
                'confidence': float(avg_confidence),
                'model_predictions': predictions,
                'model_confidences': confidences,
                'features_used': len(features[0])
            }
            
        except Exception as e:
            print(f"Error in prediction: {e}")
            return {'is_anomaly': False, 'confidence': 0.5, 'error': str(e)}

# Initialize Flask app
app = Flask(__name__)
CORS(app)

# Initialize ML service
ml_service = MLModelService()

@app.route('/health', methods=['GET'])
def health():
    """Health check endpoint"""
    return jsonify({
        'status': 'OK',
        'models_loaded': len(ml_service.models),
        'scalers_loaded': len(ml_service.scalers),
        'timestamp': datetime.now().isoformat()
    })

@app.route('/predict', methods=['POST'])
def predict():
    """Predict anomaly for packet data"""
    try:
        packet_data = request.json
        
        if not packet_data:
            return jsonify({'error': 'No packet data provided'}), 400
        
        # Get ML prediction
        prediction = ml_service.predict_anomaly(packet_data)
        
        # Add timestamp
        prediction['timestamp'] = datetime.now().isoformat()
        
        return jsonify(prediction)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/models/info', methods=['GET'])
def models_info():
    """Get information about loaded models"""
    return jsonify({
        'models': list(ml_service.models.keys()),
        'scalers': list(ml_service.scalers.keys()),
        'metadata': ml_service.metadata
    })

if __name__ == '__main__':
    print("Starting ML Model Service...")
    
    # Load models
    if ml_service.load_models():
        print("ML models loaded successfully!")
        print(f"Available models: {list(ml_service.models.keys())}")
        print(f"Available scalers: {list(ml_service.scalers.keys())}")
        
        # Start Flask server
        print("Starting Flask server on port 5000...")
        app.run(host='0.0.0.0', port=5000, debug=False)
    else:
        print("Failed to load ML models!")
        sys.exit(1)
