#!/usr/bin/env python3
"""
Model Manager - Utility script for managing trained ML models
============================================================

This script provides utilities to:
- List available trained models
- Load and use saved models
- Clean up old model files
- Test model functionality

Author: Network Security Team
Date: 2024
"""

import os
import json
import joblib
from datetime import datetime
from typing import List, Dict, Any
import pandas as pd
import numpy as np


class ModelManager:
    """Utility class for managing trained ML models."""
    
    def __init__(self, models_dir: str = "data/trained_models"):
        """Initialize the model manager."""
        self.models_dir = models_dir
        self.models = {}
        self.scalers = {}
        self.metadata = {}
        self.feature_columns = []
    
    def list_models(self) -> Dict[str, List[str]]:
        """List all available trained models."""
        if not os.path.exists(self.models_dir):
            print(f"Models directory '{self.models_dir}' not found.")
            return {}
        
        models = {
            'batch_models': [],
            'streaming_models': [],
            'metadata_files': []
        }
        
        for file in os.listdir(self.models_dir):
            if file.endswith('.joblib'):
                if file.startswith('streaming_'):
                    models['streaming_models'].append(file)
                else:
                    models['batch_models'].append(file)
            elif file.endswith('.json'):
                models['metadata_files'].append(file)
        
        return models
    
    def print_model_info(self):
        """Print information about available models."""
        models = self.list_models()
        
        print("\n" + "="*60)
        print("AVAILABLE TRAINED MODELS")
        print("="*60)
        
        if not any(models.values()):
            print("No trained models found.")
            return
        
        # Print batch models
        if models['batch_models']:
            print("\nBatch Analysis Models:")
            for model in sorted(models['batch_models']):
                timestamp = self._extract_timestamp(model)
                print(f"  - {model} (trained: {timestamp})")
        
        # Print streaming models
        if models['streaming_models']:
            print("\nStreaming Analysis Models:")
            for model in sorted(models['streaming_models']):
                timestamp = self._extract_timestamp(model)
                print(f"  - {model} (trained: {timestamp})")
        
        # Print metadata
        if models['metadata_files']:
            print("\nModel Metadata:")
            for metadata_file in sorted(models['metadata_files']):
                timestamp = self._extract_timestamp(metadata_file)
                print(f"  - {metadata_file} (created: {timestamp})")
        
        print("="*60)
    
    def _extract_timestamp(self, filename: str) -> str:
        """Extract timestamp from filename."""
        try:
            parts = filename.split('_')
            timestamp_str = parts[-1].replace('.joblib', '').replace('.json', '')
            # Try to parse and format timestamp
            timestamp = datetime.strptime(timestamp_str, "%Y%m%d_%H%M%S")
            return timestamp.strftime("%Y-%m-%d %H:%M:%S")
        except:
            return "Unknown"
    
    def load_model_metadata(self, timestamp: str = None, model_type: str = "batch") -> Dict[str, Any]:
        """Load model metadata."""
        if timestamp is None:
            # Find the most recent metadata file
            metadata_files = [f for f in os.listdir(self.models_dir) 
                            if f.endswith('.json') and model_type in f]
            if not metadata_files:
                return {}
            timestamp = self._extract_timestamp(max(metadata_files))
            timestamp = timestamp.replace("-", "").replace(":", "").replace(" ", "_")
        
        metadata_file = f"{model_type}_model_metadata_{timestamp}.json"
        metadata_path = os.path.join(self.models_dir, metadata_file)
        
        if os.path.exists(metadata_path):
            with open(metadata_path, 'r') as f:
                return json.load(f)
        return {}
    
    def test_model_prediction(self, model_type: str = "batch", timestamp: str = None):
        """Test model prediction with sample data."""
        print(f"\nTesting {model_type} model prediction...")
        
        # Load metadata to get feature columns
        metadata = self.load_model_metadata(timestamp, model_type)
        if not metadata:
            print(f"No metadata found for {model_type} models.")
            return
        
        feature_columns = metadata.get('feature_columns', [])
        if not feature_columns:
            print("No feature columns found in metadata.")
            return
        
        # Create sample data
        sample_data = {}
        for col in feature_columns:
            if 'count' in col.lower():
                sample_data[col] = np.random.randint(10, 100)
            elif 'avg' in col.lower() or 'mean' in col.lower():
                sample_data[col] = np.random.uniform(50, 500)
            elif 'unique' in col.lower():
                sample_data[col] = np.random.randint(1, 20)
            elif 'bytes' in col.lower():
                sample_data[col] = np.random.randint(1000, 10000)
            elif 'seconds' in col.lower():
                sample_data[col] = np.random.uniform(1, 60)
            elif 'per_second' in col.lower():
                sample_data[col] = np.random.uniform(0.1, 10)
            else:
                sample_data[col] = np.random.uniform(0, 100)
        
        print(f"Sample data created with {len(sample_data)} features:")
        for col, value in sample_data.items():
            print(f"  {col}: {value:.2f}")
        
        # Load models and scaler
        try:
            if timestamp is None:
                # Find most recent models
                model_files = [f for f in os.listdir(self.models_dir) 
                              if f.startswith(model_type) and f.endswith('.joblib') and 'scaler' not in f]
                if not model_files:
                    print(f"No {model_type} model files found.")
                    return
                timestamp = self._extract_timestamp(max(model_files))
                timestamp = timestamp.replace("-", "").replace(":", "").replace(" ", "_")
            
            # Load scaler
            scaler_path = os.path.join(self.models_dir, f"{model_type}_standard_scaler_{timestamp}.joblib")
            if not os.path.exists(scaler_path):
                print(f"Scaler not found: {scaler_path}")
                return
            
            scaler = joblib.load(scaler_path)
            print(f"Loaded scaler from: {scaler_path}")
            
            # Prepare sample data
            X = np.array([sample_data[col] for col in feature_columns]).reshape(1, -1)
            X_scaled = scaler.transform(X)
            
            # Test each model
            for model_name in ['isolation_forest', 'one_class_svm', 'local_outlier_factor']:
                model_path = os.path.join(self.models_dir, f"{model_type}_{model_name}_{timestamp}.joblib")
                if os.path.exists(model_path):
                    model = joblib.load(model_path)
                    
                    if model_name == 'local_outlier_factor':
                        prediction = model.fit_predict(X_scaled)
                        score = model.negative_outlier_factor_
                    else:
                        prediction = model.predict(X_scaled)
                        score = model.decision_function(X_scaled)
                    
                    anomaly_status = "ANOMALY" if prediction[0] == -1 else "NORMAL"
                    print(f"  {model_name}: {anomaly_status} (score: {score[0]:.3f})")
                else:
                    print(f"  {model_name}: Model file not found")
        
        except Exception as e:
            print(f"Error testing model: {e}")
    
    def cleanup_old_models(self, keep_days: int = 7):
        """Clean up old model files."""
        if not os.path.exists(self.models_dir):
            print(f"Models directory '{self.models_dir}' not found.")
            return
        
        cutoff_date = datetime.now().timestamp() - (keep_days * 24 * 3600)
        deleted_files = []
        
        for file in os.listdir(self.models_dir):
            file_path = os.path.join(self.models_dir, file)
            if os.path.isfile(file_path):
                file_time = os.path.getmtime(file_path)
                if file_time < cutoff_date:
                    try:
                        os.remove(file_path)
                        deleted_files.append(file)
                    except Exception as e:
                        print(f"Error deleting {file}: {e}")
        
        if deleted_files:
            print(f"Deleted {len(deleted_files)} old model files:")
            for file in deleted_files:
                print(f"  - {file}")
        else:
            print("No old model files found to delete.")
    
    def load_models(self, timestamp: str = None, model_type: str = "batch") -> bool:
        """Load trained models and scalers into memory."""
        try:
            if not os.path.exists(self.models_dir):
                print(f"Models directory '{self.models_dir}' not found.")
                return False
            
            # Find the most recent models if timestamp not specified
            if timestamp is None:
                model_files = [f for f in os.listdir(self.models_dir) 
                              if f.startswith(model_type) and f.endswith('.joblib') and 'scaler' not in f]
                if not model_files:
                    print(f"No {model_type} model files found.")
                    return False
                
                # Extract timestamp from the most recent model file
                latest_file = max(model_files)
                timestamp = self._extract_timestamp(latest_file)
                timestamp = timestamp.replace("-", "").replace(":", "").replace(" ", "_")
            
            # Load metadata
            self.metadata = self.load_model_metadata(timestamp, model_type)
            self.feature_columns = self.metadata.get('feature_columns', [])
            
            # Load scaler
            scaler_path = os.path.join(self.models_dir, f"{model_type}_standard_scaler_{timestamp}.joblib")
            if os.path.exists(scaler_path):
                self.scalers['standard'] = joblib.load(scaler_path)
                print(f"Loaded scaler from: {scaler_path}")
            
            # Load models
            for model_name in ['isolation_forest', 'one_class_svm', 'local_outlier_factor']:
                model_path = os.path.join(self.models_dir, f"{model_type}_{model_name}_{timestamp}.joblib")
                if os.path.exists(model_path):
                    self.models[model_name] = joblib.load(model_path)
                    print(f"Loaded {model_name} model from: {model_path}")
            
            print(f"Successfully loaded {len(self.models)} models with {len(self.feature_columns)} features")
            return len(self.models) > 0
            
        except Exception as e:
            print(f"Error loading models: {e}")
            return False
    
    def predict_single_packet(self, packet_data: Dict[str, Any]) -> Dict[str, Any]:
        """Predict anomaly for a single packet."""
        if not self.models or not self.scalers:
            return {
                'is_anomaly': False,
                'risk_level': 'LOW',
                'reason': 'Models not loaded',
                'anomaly_score': 0.0,
                'model_predictions': {}
            }
        
        try:
            # Extract features from packet data
            features = self._extract_packet_features(packet_data)
            
            if not features:
                return {
                    'is_anomaly': False,
                    'risk_level': 'LOW',
                    'reason': 'Could not extract features',
                    'anomaly_score': 0.0,
                    'model_predictions': {}
                }
            
            # Prepare feature vector
            feature_vector = []
            for col in self.feature_columns:
                feature_vector.append(features.get(col, 0))
            
            X = np.array(feature_vector).reshape(1, -1)
            X_scaled = self.scalers['standard'].transform(X)
            
            # Get predictions from all models
            model_predictions = {}
            anomaly_scores = []
            
            for model_name, model in self.models.items():
                try:
                    if model_name == 'local_outlier_factor':
                        prediction = model.fit_predict(X_scaled)
                        score = model.negative_outlier_factor_
                    else:
                        prediction = model.predict(X_scaled)
                        score = model.decision_function(X_scaled)
                    
                    is_anomaly = prediction[0] == -1
                    anomaly_score = abs(score[0]) if hasattr(score, '__len__') else abs(score)
                    
                    model_predictions[model_name] = {
                        'is_anomaly': is_anomaly,
                        'score': anomaly_score
                    }
                    
                    if is_anomaly:
                        anomaly_scores.append(anomaly_score)
                        
                except Exception as e:
                    print(f"Error with {model_name}: {e}")
                    model_predictions[model_name] = {
                        'is_anomaly': False,
                        'score': 0.0
                    }
            
            # Determine overall anomaly status
            is_anomaly = len(anomaly_scores) > 0
            max_score = max(anomaly_scores) if anomaly_scores else 0.0
            
            # Determine risk level
            if max_score > 2.0:
                risk_level = 'HIGH'
            elif max_score > 1.0:
                risk_level = 'MEDIUM'
            else:
                risk_level = 'LOW'
            
            # Generate reason
            if is_anomaly:
                anomaly_models = [name for name, pred in model_predictions.items() if pred['is_anomaly']]
                reason = f"Anomaly detected by {', '.join(anomaly_models)}"
            else:
                reason = "Normal traffic pattern"
            
            return {
                'is_anomaly': is_anomaly,
                'risk_level': risk_level,
                'reason': reason,
                'anomaly_score': max_score,
                'model_predictions': model_predictions,
                'features_used': features
            }
            
        except Exception as e:
            print(f"Error in prediction: {e}")
            return {
                'is_anomaly': False,
                'risk_level': 'LOW',
                'reason': f'Prediction error: {str(e)}',
                'anomaly_score': 0.0,
                'model_predictions': {}
            }
    
    def _extract_packet_features(self, packet_data: Dict[str, Any]) -> Dict[str, Any]:
        """Extract features from packet data for ML prediction."""
        try:
            features = {}
            
            # Basic packet features
            features['packet_length'] = packet_data.get('packet_length', 0)
            features['src_port'] = packet_data.get('src_port', 0)
            features['dst_port'] = packet_data.get('dst_port', 0)
            
            # Protocol encoding
            protocol = packet_data.get('protocol', 'unknown').upper()
            features['protocol_tcp'] = 1 if protocol == 'TCP' else 0
            features['protocol_udp'] = 1 if protocol == 'UDP' else 0
            features['protocol_icmp'] = 1 if protocol == 'ICMP' else 0
            
            # Port-based features
            features['is_well_known_port'] = 1 if packet_data.get('dst_port', 0) < 1024 else 0
            features['is_privileged_port'] = 1 if packet_data.get('src_port', 0) < 1024 else 0
            
            # IP-based features (simplified)
            src_ip = packet_data.get('src_ip', '0.0.0.0')
            dst_ip = packet_data.get('dst_ip', '0.0.0.0')
            
            # Check for private IPs
            features['src_is_private'] = self._is_private_ip(src_ip)
            features['dst_is_private'] = self._is_private_ip(dst_ip)
            
            # Packet size categories
            packet_size = packet_data.get('packet_length', 0)
            features['is_small_packet'] = 1 if packet_size < 64 else 0
            features['is_large_packet'] = 1 if packet_size > 1500 else 0
            
            # Time-based features (if timestamp available)
            timestamp = packet_data.get('timestamp')
            if timestamp:
                try:
                    from datetime import datetime
                    dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                    features['hour_of_day'] = dt.hour
                    features['day_of_week'] = dt.weekday()
                except:
                    features['hour_of_day'] = 12  # Default to noon
                    features['day_of_week'] = 0  # Default to Monday
            
            return features
            
        except Exception as e:
            print(f"Error extracting features: {e}")
            return {}
    
    def _is_private_ip(self, ip: str) -> int:
        """Check if IP is private."""
        try:
            parts = ip.split('.')
            if len(parts) != 4:
                return 0
            
            first_octet = int(parts[0])
            second_octet = int(parts[1])
            
            # Private IP ranges
            if first_octet == 10:
                return 1
            elif first_octet == 172 and 16 <= second_octet <= 31:
                return 1
            elif first_octet == 192 and second_octet == 168:
                return 1
            else:
                return 0
        except:
            return 0


def main():
    """Main function to demonstrate model management."""
    print("Model Manager - Network Traffic Analysis Models")
    print("=" * 60)
    
    manager = ModelManager()
    
    # List available models
    manager.print_model_info()
    
    # Test model prediction
    print("\nTesting model predictions...")
    manager.test_model_prediction("batch")
    manager.test_model_prediction("streaming")
    
    # Show cleanup option
    print("\nTo clean up old models (older than 7 days), run:")
    print("manager.cleanup_old_models(keep_days=7)")


if __name__ == "__main__":
    main()
