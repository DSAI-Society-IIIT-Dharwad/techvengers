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
    
    def __init__(self, models_dir: str = "trained_models"):
        """Initialize the model manager."""
        self.models_dir = models_dir
    
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
