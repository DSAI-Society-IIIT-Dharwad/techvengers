#!/usr/bin/env python3
"""
Real-Time Streaming Network Traffic Analyzer
==========================================

This system continuously processes packets in real-time, building a comprehensive
understanding of network behavior and detecting anomalies as they occur.

Features:
- Real-time packet streaming
- Sliding window analysis
- Adaptive ML models
- Continuous baseline learning
- Live anomaly detection
- Historical pattern analysis
"""

import pandas as pd
import numpy as np
import time
import threading
import queue
import json
import os
import pickle
import joblib
from datetime import datetime, timedelta
from collections import defaultdict, deque
from typing import Dict, List, Tuple, Any, Optional
import warnings
warnings.filterwarnings('ignore')

# Machine Learning imports
try:
    from sklearn.ensemble import IsolationForest
    from sklearn.svm import OneClassSVM
    from sklearn.neighbors import LocalOutlierFactor
    from sklearn.preprocessing import StandardScaler
    from sklearn.cluster import DBSCAN
    from sklearn.metrics import silhouette_score
    ML_AVAILABLE = True
except ImportError:
    print("Warning: scikit-learn not available. Install with: pip install scikit-learn")
    ML_AVAILABLE = False

# Statistical analysis
from collections import Counter
import statistics


class StreamingPacketProcessor:
    """
    Real-time packet processor that builds network understanding over time.
    """
    
    def __init__(self, 
                 window_size: int = 100,  # packets per analysis window
                 update_interval: float = 5.0,  # seconds between analysis
                 baseline_period: int = 10,  # number of windows for baseline
                 alert_file: str = "data/streaming_alerts.csv"):
        """
        Initialize the streaming processor.
        
        Args:
            window_size: Number of packets per analysis window
            update_interval: Seconds between analysis cycles
            baseline_period: Number of windows to build baseline
            alert_file: File to save real-time alerts
        """
        self.window_size = window_size
        self.update_interval = update_interval
        self.baseline_period = baseline_period
        self.alert_file = alert_file
        
        # Data structures
        self.packet_queue = queue.Queue()
        self.packet_buffer = deque(maxlen=window_size * 2)  # Keep extra for overlap
        self.baseline_data = deque(maxlen=baseline_period)
        self.historical_patterns = defaultdict(list)
        
        # ML Models
        self.models = {}
        self.scalers = {}
        self.baseline_established = False
        self.baseline_features = None
        
        # Statistics tracking
        self.ip_stats = defaultdict(lambda: {
            'packet_count': 0,
            'destinations': set(),
            'ports': set(),
            'protocols': set(),
            'packet_sizes': [],
            'timestamps': [],
            'bytes_total': 0,
            'first_seen': None,
            'last_seen': None
        })
        
        # Alert tracking
        self.alerts = []
        self.alert_thresholds = {
            'packet_rate': 1000,  # packets per second
            'destination_diversity': 50,  # unique destinations
            'port_scan_threshold': 20,  # unique ports
            'anomaly_score_threshold': 0.5
        }
        
        # Initialize alert file
        self._initialize_alert_file()
        
        # Control flags
        self.running = False
        self.analysis_thread = None
        
    def _initialize_alert_file(self):
        """Initialize the alert file with headers."""
        headers = [
            'timestamp',
            'alert_type',
            'risk_level',
            'source_ip',
            'destination_ip',
            'reason',
            'anomaly_score',
            'details',
            'window_id',
            'packet_count'
        ]
        
        if not os.path.exists(self.alert_file):
            with open(self.alert_file, 'w', newline='', encoding='utf-8') as file:
                import csv
                writer = csv.writer(file)
                writer.writerow(headers)
    
    def add_packet(self, packet_data: Dict[str, Any]):
        """
        Add a packet to the processing queue.
        
        Args:
            packet_data: Dictionary containing packet information
        """
        # Add timestamp if not present
        if 'timestamp' not in packet_data:
            packet_data['timestamp'] = datetime.now().isoformat()
        
        # Add to queue for processing
        self.packet_queue.put(packet_data)
        
        # Update IP statistics
        self._update_ip_stats(packet_data)
    
    def _update_ip_stats(self, packet_data: Dict[str, Any]):
        """Update per-IP statistics."""
        source_ip = packet_data.get('source_ip', 'unknown')
        dest_ip = packet_data.get('destination_ip', 'unknown')
        dest_port = packet_data.get('destination_port', 0)
        protocol = packet_data.get('protocol', 'unknown')
        packet_size = packet_data.get('packet_length', 0)
        timestamp = packet_data.get('timestamp', datetime.now().isoformat())
        
        stats = self.ip_stats[source_ip]
        stats['packet_count'] += 1
        stats['destinations'].add(dest_ip)
        stats['ports'].add(dest_port)
        stats['protocols'].add(protocol)
        stats['packet_sizes'].append(packet_size)
        stats['timestamps'].append(timestamp)
        stats['bytes_total'] += packet_size
        
        if stats['first_seen'] is None:
            stats['first_seen'] = timestamp
        stats['last_seen'] = timestamp
    
    def start_processing(self):
        """Start the real-time processing thread."""
        if self.running:
            print("Processor already running!")
            return
        
        self.running = True
        self.analysis_thread = threading.Thread(target=self._processing_loop, daemon=True)
        self.analysis_thread.start()
        print(f"Started streaming processor (window: {self.window_size}, interval: {self.update_interval}s)")
    
    def stop_processing(self):
        """Stop the real-time processing."""
        self.running = False
        if self.analysis_thread:
            self.analysis_thread.join()
        print("Stopped streaming processor")
    
    def _processing_loop(self):
        """Main processing loop."""
        window_id = 0
        
        while self.running:
            try:
                # Collect packets for current window
                window_packets = self._collect_window_packets()
                
                if len(window_packets) >= self.window_size:
                    window_id += 1
                    
                    # Process the window
                    self._process_window(window_packets, window_id)
                    
                    # Update baseline if needed
                    if not self.baseline_established and len(self.baseline_data) >= self.baseline_period:
                        self._establish_baseline()
                
                # Wait for next analysis cycle
                time.sleep(self.update_interval)
                
            except Exception as e:
                print(f"Error in processing loop: {e}")
                time.sleep(1)
    
    def _collect_window_packets(self) -> List[Dict[str, Any]]:
        """Collect packets for current analysis window."""
        window_packets = []
        
        # Get packets from queue
        while len(window_packets) < self.window_size and not self.packet_queue.empty():
            try:
                packet = self.packet_queue.get_nowait()
                window_packets.append(packet)
                self.packet_buffer.append(packet)
            except queue.Empty:
                break
        
        # If not enough packets from queue, use buffer
        if len(window_packets) < self.window_size and len(self.packet_buffer) >= self.window_size:
            window_packets = list(self.packet_buffer)[-self.window_size:]
        
        return window_packets
    
    def _process_window(self, packets: List[Dict[str, Any]], window_id: int):
        """Process a window of packets."""
        if len(packets) == 0:
            return
        
        print(f"\nProcessing window {window_id} ({len(packets)} packets)")
        
        # Extract features for this window
        features = self._extract_window_features(packets, window_id)
        
        # Store in baseline data if not established
        if not self.baseline_established:
            self.baseline_data.append(features)
            print(f"  Baseline data: {len(self.baseline_data)}/{self.baseline_period} windows")
            return
        
        # Detect anomalies
        anomalies = self._detect_window_anomalies(features, window_id)
        
        # Generate alerts
        if anomalies:
            self._generate_alerts(anomalies, window_id, len(packets))
        
        # Update models with new data
        self._update_models(features)
    
    def _extract_window_features(self, packets: List[Dict[str, Any]], window_id: int) -> Dict[str, Any]:
        """Extract features from a window of packets."""
        if not packets:
            return {}
        
        # Convert to DataFrame for easier analysis
        df = pd.DataFrame(packets)
        
        # Basic window features
        features = {
            'window_id': window_id,
            'packet_count': len(packets),
            'unique_source_ips': df['source_ip'].nunique(),
            'unique_dest_ips': df['destination_ip'].nunique(),
            'unique_ports': df['destination_port'].nunique(),
            'protocols': df['protocol'].nunique(),
            'avg_packet_size': df['packet_length'].mean(),
            'total_bytes': df['packet_length'].sum(),
            'time_span': self._calculate_time_span(df['timestamp']),
        }
        
        # Per-IP features
        for source_ip in df['source_ip'].unique():
            ip_data = df[df['source_ip'] == source_ip]
            features[f'ip_{source_ip}_packets'] = len(ip_data)
            features[f'ip_{source_ip}_destinations'] = ip_data['destination_ip'].nunique()
            features[f'ip_{source_ip}_ports'] = ip_data['destination_port'].nunique()
            features[f'ip_{source_ip}_bytes'] = ip_data['packet_length'].sum()
        
        # Calculate rates
        if features['time_span'] > 0:
            features['packets_per_second'] = features['packet_count'] / features['time_span']
            features['bytes_per_second'] = features['total_bytes'] / features['time_span']
        else:
            features['packets_per_second'] = 0
            features['bytes_per_second'] = 0
        
        return features
    
    def _calculate_time_span(self, timestamps: pd.Series) -> float:
        """Calculate time span in seconds."""
        try:
            timestamps = pd.to_datetime(timestamps)
            return (timestamps.max() - timestamps.min()).total_seconds()
        except:
            return 0.0
    
    def _establish_baseline(self):
        """Establish baseline patterns from historical data."""
        print(f"\nEstablishing baseline from {len(self.baseline_data)} windows...")
        
        if not ML_AVAILABLE:
            print("ML not available, using statistical baseline")
            self._establish_statistical_baseline()
            return
        
        # Convert baseline data to feature matrix
        baseline_features = []
        for window_features in self.baseline_data:
            feature_vector = self._features_to_vector(window_features)
            if feature_vector is not None:
                baseline_features.append(feature_vector)
        
        if len(baseline_features) < 2:
            print("Not enough baseline data for ML models")
            self._establish_statistical_baseline()
            return
        
        # Train ML models
        X = np.array(baseline_features)
        
        # Scale features
        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(X)
        self.scalers['standard'] = scaler
        
        # Train Isolation Forest
        iso_forest = IsolationForest(
            contamination=0.1,
            random_state=42,
            n_estimators=100
        )
        iso_forest.fit(X_scaled)
        self.models['isolation_forest'] = iso_forest
        
        # Train One-Class SVM
        oc_svm = OneClassSVM(
            nu=0.1,
            kernel='rbf',
            gamma='scale'
        )
        oc_svm.fit(X_scaled)
        self.models['one_class_svm'] = oc_svm
        
        # Train Local Outlier Factor
        if len(X_scaled) > 1:
            lof = LocalOutlierFactor(
                n_neighbors=min(20, len(X_scaled)-1),
                contamination=0.1
            )
            lof.fit(X_scaled)
            self.models['local_outlier_factor'] = lof
        
        # Store baseline features for comparison
        self.baseline_features = X_scaled
        
        self.baseline_established = True
        print("Baseline established! ML models trained.")
        
        # Save models to disk
        self.save_models()
    
    def _establish_statistical_baseline(self):
        """Establish statistical baseline without ML."""
        print("Establishing statistical baseline...")
        
        # Calculate statistical thresholds
        packet_counts = [w['packet_count'] for w in self.baseline_data]
        dest_counts = [w['unique_dest_ips'] for w in self.baseline_data]
        port_counts = [w['unique_ports'] for w in self.baseline_data]
        
        self.baseline_stats = {
            'packet_count_mean': np.mean(packet_counts),
            'packet_count_std': np.std(packet_counts),
            'dest_count_mean': np.mean(dest_counts),
            'dest_count_std': np.std(dest_counts),
            'port_count_mean': np.mean(port_counts),
            'port_count_std': np.std(port_counts),
        }
        
        self.baseline_established = True
        print("Statistical baseline established!")
    
    def _features_to_vector(self, features: Dict[str, Any]) -> Optional[np.ndarray]:
        """Convert features dictionary to numpy vector."""
        try:
            # Select numeric features
            numeric_features = [
                'packet_count', 'unique_source_ips', 'unique_dest_ips',
                'unique_ports', 'protocols', 'avg_packet_size', 'total_bytes',
                'time_span', 'packets_per_second', 'bytes_per_second'
            ]
            
            vector = []
            for feature in numeric_features:
                vector.append(features.get(feature, 0))
            
            return np.array(vector)
        except Exception as e:
            print(f"Error converting features to vector: {e}")
            return None
    
    def _detect_window_anomalies(self, features: Dict[str, Any], window_id: int) -> List[Dict[str, Any]]:
        """Detect anomalies in current window."""
        anomalies = []
        
        if not self.baseline_established:
            return anomalies
        
        # ML-based detection
        if ML_AVAILABLE and self.models:
            ml_anomalies = self._detect_ml_anomalies(features, window_id)
            anomalies.extend(ml_anomalies)
        
        # Statistical detection
        stat_anomalies = self._detect_statistical_anomalies(features, window_id)
        anomalies.extend(stat_anomalies)
        
        # Rule-based detection
        rule_anomalies = self._detect_rule_based_anomalies(features, window_id)
        anomalies.extend(rule_anomalies)
        
        return anomalies
    
    def _detect_ml_anomalies(self, features: Dict[str, Any], window_id: int) -> List[Dict[str, Any]]:
        """Detect anomalies using ML models."""
        anomalies = []
        
        feature_vector = self._features_to_vector(features)
        if feature_vector is None:
            return anomalies
        
        X_scaled = self.scalers['standard'].transform([feature_vector])
        
        # Check each model
        for model_name, model in self.models.items():
            try:
                if model_name == 'local_outlier_factor':
                    prediction = model.fit_predict(X_scaled)
                    score = model.negative_outlier_factor_
                else:
                    prediction = model.predict(X_scaled)
                    score = model.decision_function(X_scaled)
                
                if prediction[0] == -1:  # Anomaly detected
                    anomaly_score = abs(score[0]) if hasattr(score, '__len__') else abs(score)
                    
                    anomalies.append({
                        'type': 'ML_ANOMALY',
                        'model': model_name,
                        'score': anomaly_score,
                        'features': features,
                        'window_id': window_id
                    })
            except Exception as e:
                print(f"Error in {model_name}: {e}")
        
        return anomalies
    
    def _detect_statistical_anomalies(self, features: Dict[str, Any], window_id: int) -> List[Dict[str, Any]]:
        """Detect anomalies using statistical methods."""
        anomalies = []
        
        if not hasattr(self, 'baseline_stats'):
            return anomalies
        
        # Check packet count anomaly
        packet_count = features.get('packet_count', 0)
        mean = self.baseline_stats['packet_count_mean']
        std = self.baseline_stats['packet_count_std']
        
        if std > 0 and abs(packet_count - mean) > 2 * std:
            anomalies.append({
                'type': 'STATISTICAL',
                'metric': 'packet_count',
                'value': packet_count,
                'threshold': mean + 2 * std,
                'score': abs(packet_count - mean) / std,
                'features': features,
                'window_id': window_id
            })
        
        # Check destination diversity anomaly
        dest_count = features.get('unique_dest_ips', 0)
        mean = self.baseline_stats['dest_count_mean']
        std = self.baseline_stats['dest_count_std']
        
        if std > 0 and abs(dest_count - mean) > 2 * std:
            anomalies.append({
                'type': 'STATISTICAL',
                'metric': 'destination_diversity',
                'value': dest_count,
                'threshold': mean + 2 * std,
                'score': abs(dest_count - mean) / std,
                'features': features,
                'window_id': window_id
            })
        
        return anomalies
    
    def _detect_rule_based_anomalies(self, features: Dict[str, Any], window_id: int) -> List[Dict[str, Any]]:
        """Detect anomalies using rule-based methods."""
        anomalies = []
        
        # High packet rate
        packets_per_second = features.get('packets_per_second', 0)
        if packets_per_second > self.alert_thresholds['packet_rate']:
            anomalies.append({
                'type': 'RULE_BASED',
                'rule': 'high_packet_rate',
                'value': packets_per_second,
                'threshold': self.alert_thresholds['packet_rate'],
                'score': packets_per_second / self.alert_thresholds['packet_rate'],
                'features': features,
                'window_id': window_id
            })
        
        # High destination diversity
        dest_count = features.get('unique_dest_ips', 0)
        if dest_count > self.alert_thresholds['destination_diversity']:
            anomalies.append({
                'type': 'RULE_BASED',
                'rule': 'high_destination_diversity',
                'value': dest_count,
                'threshold': self.alert_thresholds['destination_diversity'],
                'score': dest_count / self.alert_thresholds['destination_diversity'],
                'features': features,
                'window_id': window_id
            })
        
        # Port scan detection
        port_count = features.get('unique_ports', 0)
        if port_count > self.alert_thresholds['port_scan_threshold']:
            anomalies.append({
                'type': 'RULE_BASED',
                'rule': 'port_scan',
                'value': port_count,
                'threshold': self.alert_thresholds['port_scan_threshold'],
                'score': port_count / self.alert_thresholds['port_scan_threshold'],
                'features': features,
                'window_id': window_id
            })
        
        return anomalies
    
    def _generate_alerts(self, anomalies: List[Dict[str, Any]], window_id: int, packet_count: int):
        """Generate alerts from detected anomalies."""
        for anomaly in anomalies:
            # Determine risk level
            score = anomaly.get('score', 0)
            if score > 2.0:
                risk_level = 'HIGH'
            elif score > 1.0:
                risk_level = 'MEDIUM'
            else:
                risk_level = 'LOW'
            
            # Create alert
            alert = {
                'timestamp': datetime.now().isoformat(),
                'alert_type': anomaly['type'],
                'risk_level': risk_level,
                'source_ip': 'Multiple',
                'destination_ip': 'Multiple',
                'reason': self._generate_reason(anomaly),
                'anomaly_score': score,
                'details': self._generate_details(anomaly),
                'window_id': window_id,
                'packet_count': packet_count
            }
            
            self.alerts.append(alert)
            self._save_alert(alert)
            self._print_alert(alert)
    
    def _generate_reason(self, anomaly: Dict[str, Any]) -> str:
        """Generate human-readable reason for anomaly."""
        if anomaly['type'] == 'ML_ANOMALY':
            return f"{anomaly['model']} detected anomaly"
        elif anomaly['type'] == 'STATISTICAL':
            return f"Statistical anomaly in {anomaly['metric']}"
        elif anomaly['type'] == 'RULE_BASED':
            return f"Rule violation: {anomaly['rule']}"
        else:
            return "Unknown anomaly type"
    
    def _generate_details(self, anomaly: Dict[str, Any]) -> str:
        """Generate detailed information about anomaly."""
        features = anomaly.get('features', {})
        
        details = []
        details.append(f"Packets: {features.get('packet_count', 0)}")
        details.append(f"Destinations: {features.get('unique_dest_ips', 0)}")
        details.append(f"Ports: {features.get('unique_ports', 0)}")
        details.append(f"PPS: {features.get('packets_per_second', 0):.2f}")
        
        if 'value' in anomaly and 'threshold' in anomaly:
            details.append(f"Value: {anomaly['value']}, Threshold: {anomaly['threshold']}")
        
        return "; ".join(details)
    
    def _save_alert(self, alert: Dict[str, Any]):
        """Save alert to CSV file."""
        try:
            with open(self.alert_file, 'a', newline='', encoding='utf-8') as file:
                import csv
                writer = csv.writer(file)
                writer.writerow([
                    alert['timestamp'],
                    alert['alert_type'],
                    alert['risk_level'],
                    alert['source_ip'],
                    alert['destination_ip'],
                    alert['reason'],
                    alert['anomaly_score'],
                    alert['details'],
                    alert['window_id'],
                    alert['packet_count']
                ])
        except Exception as e:
            print(f"Error saving alert: {e}")
    
    def _print_alert(self, alert: Dict[str, Any]):
        """Print alert to console."""
        risk_symbol = {
            'HIGH': '[HIGH]',
            'MEDIUM': '[MEDIUM]',
            'LOW': '[LOW]'
        }.get(alert['risk_level'], '[UNKNOWN]')
        
        print(f"\n{risk_symbol} STREAMING ALERT: {alert['alert_type']} - {alert['risk_level']} RISK")
        print(f"   Window: {alert['window_id']}, Packets: {alert['packet_count']}")
        print(f"   Reason: {alert['reason']}")
        print(f"   Score: {alert['anomaly_score']:.3f}")
        print(f"   Details: {alert['details']}")
        print(f"   Time: {alert['timestamp']}")
        print("-" * 80)
    
    def _update_models(self, features: Dict[str, Any]):
        """Update ML models with new data (online learning)."""
        if not ML_AVAILABLE or not self.models:
            return
        
        # For now, we'll use batch learning
        # In a production system, you'd implement online learning algorithms
        pass
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get current statistics."""
        return {
            'total_packets_processed': sum(stats['packet_count'] for stats in self.ip_stats.values()),
            'unique_ips': len(self.ip_stats),
            'baseline_established': self.baseline_established,
            'total_alerts': len(self.alerts),
            'windows_processed': len(self.baseline_data),
            'current_window_size': len(self.packet_buffer),
            'queue_size': self.packet_queue.qsize()
        }
    
    def save_models(self):
        """Save trained models and scalers to disk."""
        if not self.models:
            print("No models to save.")
            return
        
        # Create models directory if it doesn't exist
        models_dir = "data/trained_models"
        if not os.path.exists(models_dir):
            os.makedirs(models_dir)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        try:
            # Save each model
            for model_name, model in self.models.items():
                model_path = os.path.join(models_dir, f"streaming_{model_name}_{timestamp}.joblib")
                joblib.dump(model, model_path)
                print(f"Saved streaming {model_name} model to: {model_path}")
            
            # Save scalers
            for scaler_name, scaler in self.scalers.items():
                scaler_path = os.path.join(models_dir, f"streaming_{scaler_name}_scaler_{timestamp}.joblib")
                joblib.dump(scaler, scaler_path)
                print(f"Saved streaming {scaler_name} scaler to: {scaler_path}")
            
            # Save model metadata
            metadata = {
                'timestamp': timestamp,
                'model_type': 'streaming',
                'models_trained': list(self.models.keys()),
                'scalers_trained': list(self.scalers.keys()),
                'feature_columns': [
                    'packet_count', 'unique_source_ips', 'unique_dest_ips',
                    'unique_ports', 'protocols', 'avg_packet_size', 'total_bytes',
                    'time_span', 'packets_per_second', 'bytes_per_second'
                ],
                'baseline_windows': len(self.baseline_data),
                'window_size': self.window_size,
                'update_interval': self.update_interval
            }
            
            metadata_path = os.path.join(models_dir, f"streaming_model_metadata_{timestamp}.json")
            with open(metadata_path, 'w') as f:
                json.dump(metadata, f, indent=2)
            print(f"Saved streaming model metadata to: {metadata_path}")
            
            print(f"\nAll streaming models saved successfully to '{models_dir}' directory!")
            
        except Exception as e:
            print(f"Error saving streaming models: {e}")
    
    def load_models(self, timestamp: str = None):
        """Load previously trained streaming models from disk."""
        models_dir = "data/trained_models"
        
        if not os.path.exists(models_dir):
            print(f"Models directory '{models_dir}' not found.")
            return False
        
        try:
            # Find the most recent streaming models if timestamp not specified
            if timestamp is None:
                model_files = [f for f in os.listdir(models_dir) if f.startswith('streaming_') and f.endswith('.joblib') and 'scaler' not in f]
                if not model_files:
                    print("No streaming model files found.")
                    return False
                
                # Extract timestamps and find the most recent
                timestamps = set()
                for file in model_files:
                    parts = file.split('_')
                    if len(parts) >= 3:
                        timestamps.add(parts[-1].replace('.joblib', ''))
                
                if not timestamps:
                    print("Could not extract timestamp from streaming model files.")
                    return False
                
                timestamp = max(timestamps)
                print(f"Loading streaming models with timestamp: {timestamp}")
            
            # Load models
            for model_name in ['isolation_forest', 'one_class_svm', 'local_outlier_factor']:
                model_path = os.path.join(models_dir, f"streaming_{model_name}_{timestamp}.joblib")
                if os.path.exists(model_path):
                    self.models[model_name] = joblib.load(model_path)
                    print(f"Loaded streaming {model_name} model from: {model_path}")
            
            # Load scalers
            scaler_path = os.path.join(models_dir, f"streaming_standard_scaler_{timestamp}.joblib")
            if os.path.exists(scaler_path):
                self.scalers['standard'] = joblib.load(scaler_path)
                print(f"Loaded streaming standard scaler from: {scaler_path}")
            
            # Load metadata
            metadata_path = os.path.join(models_dir, f"streaming_model_metadata_{timestamp}.json")
            if os.path.exists(metadata_path):
                with open(metadata_path, 'r') as f:
                    metadata = json.load(f)
                print(f"Loaded streaming model metadata from: {metadata_path}")
                print(f"Streaming models trained on: {metadata.get('timestamp', 'Unknown')}")
            
            print("Streaming models loaded successfully!")
            return True
            
        except Exception as e:
            print(f"Error loading streaming models: {e}")
            return False
    
    def print_statistics(self):
        """Print current statistics."""
        stats = self.get_statistics()
        
        print("\n" + "="*60)
        print("STREAMING PROCESSOR STATISTICS")
        print("="*60)
        print(f"Total packets processed: {stats['total_packets_processed']}")
        print(f"Unique IPs tracked: {stats['unique_ips']}")
        print(f"Baseline established: {stats['baseline_established']}")
        print(f"Total alerts generated: {stats['total_alerts']}")
        print(f"Windows processed: {stats['windows_processed']}")
        print(f"Current buffer size: {stats['current_window_size']}")
        print(f"Queue size: {stats['queue_size']}")
        print("="*60)


def main():
    """Main function to demonstrate streaming analysis."""
    print("Real-Time Streaming Network Traffic Analyzer")
    print("=" * 60)
    
    # Create processor
    processor = StreamingPacketProcessor(
        window_size=50,  # Analyze every 50 packets
        update_interval=3.0,  # Check every 3 seconds
        baseline_period=5  # Build baseline from 5 windows
    )
    
    # Start processing
    processor.start_processing()
    
    try:
        print("Streaming processor started. Press Ctrl+C to stop.")
        print("The processor will build a baseline and then detect anomalies.")
        
        # Simulate packet input (in real use, this would come from packet capture)
        packet_counter = 0
        
        while True:
            # Simulate packet data
            packet_data = {
                'source_ip': '10.0.6.176',
                'destination_ip': f'192.168.1.{packet_counter % 10}',
                'destination_port': 443,
                'protocol': 'TCP',
                'packet_length': 64,
                'timestamp': datetime.now().isoformat()
            }
            
            # Add packet to processor
            processor.add_packet(packet_data)
            packet_counter += 1
            
            # Print statistics every 10 packets
            if packet_counter % 10 == 0:
                processor.print_statistics()
            
            # Sleep to simulate real-time
            time.sleep(0.1)
            
    except KeyboardInterrupt:
        print("\nStopping streaming processor...")
        processor.stop_processing()
        
        # Final statistics
        processor.print_statistics()
        
        print(f"\nAlerts saved to: {processor.alert_file}")
        print("Streaming analysis complete!")


if __name__ == "__main__":
    main()
