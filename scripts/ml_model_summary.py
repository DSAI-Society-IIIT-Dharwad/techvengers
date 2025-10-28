#!/usr/bin/env python3
"""
ML Model Training Summary and Statistics
=======================================

This script provides a comprehensive summary of all trained ML models,
including training statistics, performance metrics, and model details.
"""

import os
import json
import joblib
import numpy as np
import pandas as pd
from datetime import datetime
from typing import Dict, List, Any

class MLModelSummary:
    """Comprehensive ML model analysis and summary."""
    
    def __init__(self, models_dir: str = "trained_models"):
        """Initialize the model summary analyzer."""
        self.models_dir = models_dir
        self.batch_models = {}
        self.streaming_models = {}
        self.batch_metadata = {}
        self.streaming_metadata = {}
    
    def load_model_info(self):
        """Load all model information and metadata."""
        if not os.path.exists(self.models_dir):
            print(f"Models directory '{self.models_dir}' not found!")
            return False
        
        # Load batch models metadata
        batch_metadata_files = [f for f in os.listdir(self.models_dir) 
                               if f.startswith('model_metadata') and not f.startswith('streaming_')]
        if batch_metadata_files:
            with open(os.path.join(self.models_dir, batch_metadata_files[0]), 'r') as f:
                self.batch_metadata = json.load(f)
        
        # Load streaming models metadata
        streaming_metadata_files = [f for f in os.listdir(self.models_dir) 
                                   if f.startswith('streaming_model_metadata')]
        if streaming_metadata_files:
            with open(os.path.join(self.models_dir, streaming_metadata_files[0]), 'r') as f:
                self.streaming_metadata = json.load(f)
        
        return True
    
    def analyze_model_performance(self):
        """Analyze model performance and characteristics."""
        print("=" * 80)
        print("ML MODEL TRAINING SUMMARY & STATISTICS")
        print("=" * 80)
        
        # Overall statistics
        total_files = len([f for f in os.listdir(self.models_dir) if f.endswith('.joblib')])
        total_size = sum(os.path.getsize(os.path.join(self.models_dir, f)) 
                        for f in os.listdir(self.models_dir))
        
        print(f"\nOVERALL STATISTICS:")
        print(f"  Total model files: {total_files}")
        print(f"  Total storage used: {total_size:,} bytes ({total_size/1024:.1f} KB)")
        print(f"  Training date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
        # Batch models analysis
        if self.batch_metadata:
            print(f"\n" + "="*60)
            print("BATCH ANALYSIS MODELS")
            print("="*60)
            
            timestamp = self.batch_metadata.get('timestamp', 'Unknown')
            print(f"Training timestamp: {timestamp}")
            print(f"Model type: Batch/Offline Analysis")
            
            # Model details
            models_trained = self.batch_metadata.get('models_trained', [])
            print(f"\nModels trained: {len(models_trained)}")
            for i, model in enumerate(models_trained, 1):
                print(f"  {i}. {model.upper()}")
            
            # Feature analysis
            feature_columns = self.batch_metadata.get('feature_columns', [])
            print(f"\nFeature engineering:")
            print(f"  Total features: {len(feature_columns)}")
            print(f"  Feature categories:")
            
            feature_categories = {
                'Packet Statistics': [f for f in feature_columns if 'packet' in f.lower()],
                'Network Metrics': [f for f in feature_columns if any(x in f.lower() for x in ['destination', 'port', 'protocol'])],
                'Time-based Features': [f for f in feature_columns if any(x in f.lower() for x in ['time', 'duration', 'second'])],
                'Protocol Analysis': [f for f in feature_columns if any(x in f.lower() for x in ['tcp', 'udp', 'icmp'])],
                'Traffic Patterns': [f for f in feature_columns if any(x in f.lower() for x in ['bytes', 'rate', 'per_second'])]
            }
            
            for category, features in feature_categories.items():
                if features:
                    print(f"    - {category}: {len(features)} features")
                    for feature in features[:3]:  # Show first 3 features
                        print(f"      * {feature}")
                    if len(features) > 3:
                        print(f"      * ... and {len(features)-3} more")
            
            # Training data analysis
            training_shape = self.batch_metadata.get('training_data_shape', [])
            if training_shape:
                print(f"\nTraining data:")
                print(f"  Samples (IPs analyzed): {training_shape[0]}")
                print(f"  Features per sample: {training_shape[1]}")
                print(f"  Total data points: {training_shape[0] * training_shape[1]}")
        
        # Streaming models analysis
        if self.streaming_metadata:
            print(f"\n" + "="*60)
            print("STREAMING ANALYSIS MODELS")
            print("="*60)
            
            timestamp = self.streaming_metadata.get('timestamp', 'Unknown')
            print(f"Training timestamp: {timestamp}")
            print(f"Model type: Real-time Streaming Analysis")
            
            # Model details
            models_trained = self.streaming_metadata.get('models_trained', [])
            print(f"\nModels trained: {len(models_trained)}")
            for i, model in enumerate(models_trained, 1):
                print(f"  {i}. {model.upper()}")
            
            # Streaming-specific parameters
            baseline_windows = self.streaming_metadata.get('baseline_windows', 0)
            window_size = self.streaming_metadata.get('window_size', 0)
            update_interval = self.streaming_metadata.get('update_interval', 0)
            
            print(f"\nStreaming parameters:")
            print(f"  Baseline windows: {baseline_windows}")
            print(f"  Window size: {window_size} packets")
            print(f"  Update interval: {update_interval} seconds")
            
            # Feature analysis
            feature_columns = self.streaming_metadata.get('feature_columns', [])
            print(f"\nFeature engineering:")
            print(f"  Total features: {len(feature_columns)}")
            print(f"  Real-time features:")
            for feature in feature_columns:
                print(f"    - {feature}")
        
        # Model comparison
        if self.batch_metadata and self.streaming_metadata:
            print(f"\n" + "="*60)
            print("MODEL COMPARISON")
            print("="*60)
            
            batch_features = len(self.batch_metadata.get('feature_columns', []))
            streaming_features = len(self.streaming_metadata.get('feature_columns', []))
            
            print(f"Feature complexity:")
            print(f"  Batch models: {batch_features} features (comprehensive analysis)")
            print(f"  Streaming models: {streaming_features} features (real-time optimized)")
            print(f"  Complexity ratio: {batch_features/streaming_features:.1f}:1")
            
            print(f"\nUse cases:")
            print(f"  Batch models: Deep analysis, forensic investigation, comprehensive reports")
            print(f"  Streaming models: Real-time monitoring, live threat detection, continuous surveillance")
        
        # Performance insights
        print(f"\n" + "="*60)
        print("PERFORMANCE INSIGHTS")
        print("="*60)
        
        print(f"Model efficiency:")
        print(f"  - Isolation Forest: Fast training, good for high-dimensional data")
        print(f"  - One-Class SVM: Effective for novelty detection, kernel-based")
        print(f"  - Local Outlier Factor: Density-based, good for local anomalies")
        
        print(f"\nAnomaly detection capabilities:")
        print(f"  - Network scanning detection")
        print(f"  - DDoS attack identification")
        print(f"  - Unusual traffic pattern recognition")
        print(f"  - Protocol anomaly detection")
        print(f"  - Time-based pattern analysis")
        
        # Recommendations
        print(f"\n" + "="*60)
        print("RECOMMENDATIONS")
        print("="*60)
        
        print(f"Model usage:")
        print(f"  1. Use batch models for comprehensive analysis of historical data")
        print(f"  2. Use streaming models for real-time network monitoring")
        print(f"  3. Combine both approaches for complete network security coverage")
        
        print(f"\nNext steps:")
        print(f"  1. Test models with new packet data")
        print(f"  2. Fine-tune anomaly thresholds based on false positive rates")
        print(f"  3. Implement model retraining schedule")
        print(f"  4. Set up automated alerting based on model predictions")
        
        print("=" * 80)
    
    def generate_model_report(self):
        """Generate a detailed model report."""
        if not self.load_model_info():
            return
        
        self.analyze_model_performance()
        
        # Save report to file
        report_file = f"ml_model_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        with open(report_file, 'w') as f:
            # Redirect print output to file (simplified version)
            f.write("ML Model Training Report\n")
            f.write("=" * 50 + "\n")
            f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Models directory: {self.models_dir}\n")
            f.write(f"Batch models: {len(self.batch_metadata.get('models_trained', []))}\n")
            f.write(f"Streaming models: {len(self.streaming_metadata.get('models_trained', []))}\n")
        
        print(f"\nDetailed report saved to: {report_file}")

def main():
    """Main function to generate ML model summary."""
    print("Generating ML Model Training Summary...")
    
    analyzer = MLModelSummary()
    analyzer.generate_model_report()

if __name__ == "__main__":
    main()
