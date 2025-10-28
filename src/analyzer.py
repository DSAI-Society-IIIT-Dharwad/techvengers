#!/usr/bin/env python3
"""
Network Traffic Analyzer - Part 2: Analysis and Detection (AI/ML Logic)
========================================================================

This module analyzes captured packet data and detects suspicious network behavior
using machine learning algorithms and statistical analysis.

Author: Network Security Team
Date: 2024
"""

import pandas as pd
import numpy as np
import csv
import os
import pickle
import joblib
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Any
import warnings
warnings.filterwarnings('ignore')

# Machine Learning imports
try:
    from sklearn.ensemble import IsolationForest
    from sklearn.svm import OneClassSVM
    from sklearn.neighbors import LocalOutlierFactor
    from sklearn.preprocessing import StandardScaler, MinMaxScaler
    from sklearn.metrics import classification_report
    from sklearn.model_selection import train_test_split
    ML_AVAILABLE = True
except ImportError:
    print("Warning: scikit-learn not available. Install with: pip install scikit-learn")
    ML_AVAILABLE = False

# Statistical analysis
from collections import Counter, defaultdict
import statistics


class NetworkTrafficAnalyzer:
    """
    Advanced network traffic analyzer with anomaly detection capabilities.
    """
    
    def __init__(self, packet_file: str = "data/packets_extended.csv", alert_file: str = "data/alerts.csv"):
        """
        Initialize the network traffic analyzer.
        
        Args:
            packet_file: Path to the packet data CSV file
            alert_file: Path to the alerts output CSV file
        """
        self.packet_file = packet_file
        self.alert_file = alert_file
        self.df = None
        self.features_df = None
        self.models = {}
        self.scalers = {}
        self.alerts = []
        
        # Initialize alert file
        self._initialize_alert_file()
    
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
            'details'
        ]
        
        if not os.path.exists(self.alert_file):
            with open(self.alert_file, 'w', newline='', encoding='utf-8') as file:
                writer = csv.writer(file)
                writer.writerow(headers)
    
    def load_data(self) -> bool:
        """
        Load packet data from CSV file.
        
        Returns:
            True if data loaded successfully, False otherwise
        """
        try:
            if not os.path.exists(self.packet_file):
                print(f"Error: Packet file {self.packet_file} not found.")
                return False
            
            self.df = pd.read_csv(self.packet_file)
            print(f"Loaded {len(self.df)} packets from {self.packet_file}")
            
            # Basic data validation
            if len(self.df) == 0:
                print("Error: No packet data found.")
                return False
            
            return True
            
        except Exception as e:
            print(f"Error loading data: {e}")
            return False
    
    def clean_data(self):
        """Clean and preprocess the packet data."""
        print("\nCleaning and preprocessing data...")
        
        # Remove rows with missing critical data
        initial_count = len(self.df)
        
        # Handle extra columns that might exist
        required_columns = ['source_ip', 'destination_ip', 'timestamp']
        available_columns = [col for col in required_columns if col in self.df.columns]
        
        if len(available_columns) < len(required_columns):
            print(f"Warning: Missing required columns. Available: {list(self.df.columns)}")
            return False
        
        self.df = self.df.dropna(subset=available_columns)
        
        # Convert timestamp to datetime
        self.df['timestamp'] = pd.to_datetime(self.df['timestamp'], errors='coerce')
        
        # Remove rows with invalid timestamps
        self.df = self.df.dropna(subset=['timestamp'])
        
        # Convert packet_length to numeric
        if 'packet_length' in self.df.columns:
            self.df['packet_length'] = pd.to_numeric(self.df['packet_length'], errors='coerce')
            self.df['packet_length'] = self.df['packet_length'].fillna(0)
            
            # If all packet lengths are 0, set reasonable defaults based on protocol
            if self.df['packet_length'].sum() == 0:
                print("Warning: All packet lengths are 0. Setting default values based on protocol.")
                self.df.loc[self.df['protocol'] == 'TCP', 'packet_length'] = 64
                self.df.loc[self.df['protocol'] == 'UDP', 'packet_length'] = 32
                self.df.loc[self.df['protocol'] == 'ICMP', 'packet_length'] = 28
                self.df.loc[self.df['packet_length'] == 0, 'packet_length'] = 64
        else:
            # If packet_length column doesn't exist, create it with default values
            self.df['packet_length'] = 100  # Default packet size
        
        # Convert ports to numeric
        self.df['source_port'] = pd.to_numeric(self.df['source_port'], errors='coerce')
        self.df['destination_port'] = pd.to_numeric(self.df['destination_port'], errors='coerce')
        
        # Fill missing ports with 0
        self.df['source_port'] = self.df['source_port'].fillna(0)
        self.df['destination_port'] = self.df['destination_port'].fillna(0)
        
        # Filter out invalid IPs
        self.df = self.df[
            (self.df['source_ip'] != 'N/A') & 
            (self.df['destination_ip'] != 'N/A') &
            (self.df['source_ip'] != 'Unknown') &
            (self.df['destination_ip'] != 'Unknown')
        ]
        
        cleaned_count = len(self.df)
        print(f"Data cleaning: {initial_count} -> {cleaned_count} packets")
        
        if cleaned_count == 0:
            print("Error: No valid packet data after cleaning.")
            return False
        
        return True
    
    def exploratory_data_analysis(self):
        """Perform exploratory data analysis."""
        print("\n" + "="*60)
        print("EXPLORATORY DATA ANALYSIS")
        print("="*60)
        
        print(f"Dataset shape: {self.df.shape}")
        print(f"Time range: {self.df['timestamp'].min()} to {self.df['timestamp'].max()}")
        
        print("\nFirst 5 packets:")
        print(self.df.head())
        
        print("\nData types:")
        print(self.df.dtypes)
        
        print("\nBasic statistics:")
        print(self.df.describe())
        
        print("\nProtocol distribution:")
        protocol_counts = self.df['protocol'].value_counts()
        print(protocol_counts)
        
        print("\nTop 10 source IPs:")
        source_ip_counts = self.df['source_ip'].value_counts().head(10)
        print(source_ip_counts)
        
        print("\nTop 10 destination IPs:")
        dest_ip_counts = self.df['destination_ip'].value_counts().head(10)
        print(dest_ip_counts)
        
        print("\nPort distribution:")
        port_counts = self.df['destination_port'].value_counts().head(10)
        print(port_counts)
        
        print("\nPacket size statistics:")
        print(f"Average packet size: {self.df['packet_length'].mean():.2f} bytes")
        print(f"Min packet size: {self.df['packet_length'].min()} bytes")
        print(f"Max packet size: {self.df['packet_length'].max()} bytes")
        print(f"Std packet size: {self.df['packet_length'].std():.2f} bytes")
    
    def feature_engineering(self):
        """Create behavioral features for anomaly detection."""
        print("\nEngineering behavioral features...")
        
        # Sort by timestamp
        self.df = self.df.sort_values('timestamp').reset_index(drop=True)
        
        # Calculate time differences
        self.df['time_diff'] = self.df['timestamp'].diff().dt.total_seconds().fillna(0)
        
        # Create features per source IP
        features_list = []
        
        for source_ip in self.df['source_ip'].unique():
            ip_data = self.df[self.df['source_ip'] == source_ip].copy()
            
            if len(ip_data) == 0:
                continue
            
            # Basic features
            features = {
                'source_ip': source_ip,
                'packet_count': len(ip_data),
                'avg_packet_size': ip_data['packet_length'].mean(),
                'max_packet_size': ip_data['packet_length'].max(),
                'min_packet_size': ip_data['packet_length'].min(),
                'std_packet_size': ip_data['packet_length'].std(),
                'unique_destinations': ip_data['destination_ip'].nunique(),
                'unique_dest_ports': ip_data['destination_port'].nunique(),
                'avg_time_between_packets': ip_data['time_diff'].mean(),
                'max_time_between_packets': ip_data['time_diff'].max(),
                'min_time_between_packets': ip_data['time_diff'].min(),
                'total_bytes': ip_data['packet_length'].sum(),
                'protocol_diversity': ip_data['protocol'].nunique(),
                'first_timestamp': ip_data['timestamp'].min(),
                'last_timestamp': ip_data['timestamp'].max(),
                'duration_seconds': (ip_data['timestamp'].max() - ip_data['timestamp'].min()).total_seconds()
            }
            
            # Protocol-specific features
            protocol_counts = ip_data['protocol'].value_counts()
            features['tcp_packets'] = protocol_counts.get('TCP', 0)
            features['udp_packets'] = protocol_counts.get('UDP', 0)
            features['icmp_packets'] = protocol_counts.get('ICMP', 0)
            
            # Port-based features
            common_ports = [80, 443, 22, 21, 25, 53, 110, 143, 993, 995]
            features['common_port_connections'] = ip_data[
                ip_data['destination_port'].isin(common_ports)
            ].shape[0]
            
            # Suspicious port patterns
            features['high_port_connections'] = ip_data[
                ip_data['destination_port'] > 1024
            ].shape[0]
            
            # Calculate packets per second
            if features['duration_seconds'] > 0:
                features['packets_per_second'] = features['packet_count'] / features['duration_seconds']
            else:
                features['packets_per_second'] = 0
            
            # Calculate bytes per second
            if features['duration_seconds'] > 0:
                features['bytes_per_second'] = features['total_bytes'] / features['duration_seconds']
            else:
                features['bytes_per_second'] = 0
            
            features_list.append(features)
        
        # Create features DataFrame
        self.features_df = pd.DataFrame(features_list)
        
        # Fill NaN values
        numeric_columns = self.features_df.select_dtypes(include=[np.number]).columns
        self.features_df[numeric_columns] = self.features_df[numeric_columns].fillna(0)
        
        print(f"Created {len(self.features_df)} feature vectors")
        print(f"Feature columns: {list(self.features_df.columns)}")
        
        return self.features_df
    
    def train_anomaly_models(self):
        """Train multiple anomaly detection models."""
        if not ML_AVAILABLE:
            print("Machine learning libraries not available. Using statistical methods only.")
            return False
        
        print("\nTraining anomaly detection models...")
        
        # Prepare features for ML models
        feature_columns = [
            'packet_count', 'avg_packet_size', 'max_packet_size', 'std_packet_size',
            'unique_destinations', 'unique_dest_ports', 'avg_time_between_packets',
            'total_bytes', 'protocol_diversity', 'duration_seconds',
            'tcp_packets', 'udp_packets', 'icmp_packets',
            'common_port_connections', 'high_port_connections',
            'packets_per_second', 'bytes_per_second'
        ]
        
        X = self.features_df[feature_columns].values
        
        # Scale features
        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(X)
        self.scalers['standard'] = scaler
        
        # Train Isolation Forest
        iso_forest = IsolationForest(
            contamination=0.1,  # Expect 10% anomalies
            random_state=42,
            n_estimators=100
        )
        iso_forest.fit(X_scaled)
        self.models['isolation_forest'] = iso_forest
        
        # Train One-Class SVM
        oc_svm = OneClassSVM(
            nu=0.1,  # Expect 10% anomalies
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
        else:
            print("Warning: Not enough data points for LocalOutlierFactor (need > 1)")
        
        print("Models trained successfully!")
        
        # Save models to disk
        self.save_models()
        
        return True
    
    def detect_anomalies(self) -> List[Dict]:
        """
        Detect anomalies using trained models and statistical methods.
        
        Returns:
            List of anomaly alerts
        """
        print("\nDetecting anomalies...")
        alerts = []
        
        if ML_AVAILABLE and self.models:
            # ML-based anomaly detection
            feature_columns = [
                'packet_count', 'avg_packet_size', 'max_packet_size', 'std_packet_size',
                'unique_destinations', 'unique_dest_ports', 'avg_time_between_packets',
                'total_bytes', 'protocol_diversity', 'duration_seconds',
                'tcp_packets', 'udp_packets', 'icmp_packets',
                'common_port_connections', 'high_port_connections',
                'packets_per_second', 'bytes_per_second'
            ]
            
            X = self.features_df[feature_columns].values
            X_scaled = self.scalers['standard'].transform(X)
            
            # Get predictions from each model
            iso_predictions = self.models['isolation_forest'].predict(X_scaled)
            iso_scores = self.models['isolation_forest'].decision_function(X_scaled)
            
            svm_predictions = self.models['one_class_svm'].predict(X_scaled)
            svm_scores = self.models['one_class_svm'].decision_function(X_scaled)
            
            if 'local_outlier_factor' in self.models:
                lof_predictions = self.models['local_outlier_factor'].fit_predict(X_scaled)
                lof_scores = self.models['local_outlier_factor'].negative_outlier_factor_
            else:
                lof_predictions = np.ones(len(X_scaled))  # All normal
                lof_scores = np.zeros(len(X_scaled))
            
            # Combine predictions
            for i, row in self.features_df.iterrows():
                source_ip = row['source_ip']
                
                # Check if any model flags this as anomalous
                is_anomaly = (
                    iso_predictions[i] == -1 or
                    svm_predictions[i] == -1 or
                    lof_predictions[i] == -1
                )
                
                if is_anomaly:
                    # Calculate combined anomaly score
                    anomaly_score = (
                        abs(iso_scores[i]) + 
                        abs(svm_scores[i]) + 
                        abs(lof_scores[i])
                    ) / 3
                    
                    # Determine risk level
                    if anomaly_score > 0.7:
                        risk_level = "HIGH"
                    elif anomaly_score > 0.4:
                        risk_level = "MEDIUM"
                    else:
                        risk_level = "LOW"
                    
                    # Generate reason
                    reasons = []
                    if iso_predictions[i] == -1:
                        reasons.append("Isolation Forest anomaly")
                    if svm_predictions[i] == -1:
                        reasons.append("One-Class SVM anomaly")
                    if lof_predictions[i] == -1:
                        reasons.append("Local Outlier Factor anomaly")
                    
                    reason = "; ".join(reasons)
                    
                    alert = {
                        'timestamp': datetime.now().isoformat(),
                        'alert_type': 'ML_ANOMALY',
                        'risk_level': risk_level,
                        'source_ip': source_ip,
                        'destination_ip': 'Multiple',
                        'reason': reason,
                        'anomaly_score': anomaly_score,
                        'details': f"Packets: {row['packet_count']}, Destinations: {row['unique_destinations']}, PPS: {row['packets_per_second']:.2f}"
                    }
                    
                    alerts.append(alert)
        
        # Statistical anomaly detection
        alerts.extend(self._statistical_anomaly_detection())
        
        # Rule-based detection
        alerts.extend(self._rule_based_detection())
        
        self.alerts = alerts
        print(f"Generated {len(alerts)} alerts")
        
        return alerts
    
    def _statistical_anomaly_detection(self) -> List[Dict]:
        """Detect anomalies using statistical methods."""
        alerts = []
        
        # High packet count anomaly
        packet_count_mean = self.features_df['packet_count'].mean()
        packet_count_std = self.features_df['packet_count'].std()
        packet_count_threshold = packet_count_mean + 2 * packet_count_std
        
        high_packet_ips = self.features_df[
            self.features_df['packet_count'] > packet_count_threshold
        ]
        
        for _, row in high_packet_ips.iterrows():
            alert = {
                'timestamp': datetime.now().isoformat(),
                'alert_type': 'STATISTICAL',
                'risk_level': 'MEDIUM',
                'source_ip': row['source_ip'],
                'destination_ip': 'Multiple',
                'reason': f"High packet count ({row['packet_count']} packets, threshold: {packet_count_threshold:.0f})",
                'anomaly_score': (row['packet_count'] - packet_count_mean) / packet_count_std,
                'details': f"Packets: {row['packet_count']}, Avg: {packet_count_mean:.0f}, Std: {packet_count_std:.0f}"
            }
            alerts.append(alert)
        
        # High destination diversity anomaly
        dest_diversity_mean = self.features_df['unique_destinations'].mean()
        dest_diversity_std = self.features_df['unique_destinations'].std()
        dest_diversity_threshold = dest_diversity_mean + 2 * dest_diversity_std
        
        high_diversity_ips = self.features_df[
            self.features_df['unique_destinations'] > dest_diversity_threshold
        ]
        
        for _, row in high_diversity_ips.iterrows():
            alert = {
                'timestamp': datetime.now().isoformat(),
                'alert_type': 'STATISTICAL',
                'risk_level': 'HIGH',
                'source_ip': row['source_ip'],
                'destination_ip': 'Multiple',
                'reason': f"High destination diversity ({row['unique_destinations']} destinations, threshold: {dest_diversity_threshold:.0f})",
                'anomaly_score': (row['unique_destinations'] - dest_diversity_mean) / dest_diversity_std,
                'details': f"Destinations: {row['unique_destinations']}, Avg: {dest_diversity_mean:.0f}, Std: {dest_diversity_std:.0f}"
            }
            alerts.append(alert)
        
        return alerts
    
    def _rule_based_detection(self) -> List[Dict]:
        """Detect anomalies using rule-based methods."""
        alerts = []
        
        # Port scan detection
        for _, row in self.features_df.iterrows():
            if row['unique_dest_ports'] > 20:  # Threshold for port scanning
                alert = {
                    'timestamp': datetime.now().isoformat(),
                    'alert_type': 'RULE_BASED',
                    'risk_level': 'HIGH',
                    'source_ip': row['source_ip'],
                    'destination_ip': 'Multiple',
                    'reason': f"Potential port scan detected ({row['unique_dest_ports']} unique ports)",
                    'anomaly_score': row['unique_dest_ports'] / 20,  # Normalized score
                    'details': f"Unique ports: {row['unique_dest_ports']}, Threshold: 20"
                }
                alerts.append(alert)
        
        # High packet rate detection
        for _, row in self.features_df.iterrows():
            if row['packets_per_second'] > 100:  # Threshold for high packet rate
                alert = {
                    'timestamp': datetime.now().isoformat(),
                    'alert_type': 'RULE_BASED',
                    'risk_level': 'MEDIUM',
                    'source_ip': row['source_ip'],
                    'destination_ip': 'Multiple',
                    'reason': f"High packet rate detected ({row['packets_per_second']:.2f} packets/sec)",
                    'anomaly_score': row['packets_per_second'] / 100,
                    'details': f"Packets/sec: {row['packets_per_second']:.2f}, Threshold: 100"
                }
                alerts.append(alert)
        
        return alerts
    
    def save_alerts(self):
        """Save alerts to CSV file."""
        if not self.alerts:
            print("No alerts to save.")
            return
        
        with open(self.alert_file, 'a', newline='', encoding='utf-8') as file:
            writer = csv.writer(file)
            for alert in self.alerts:
                writer.writerow([
                    alert['timestamp'],
                    alert['alert_type'],
                    alert['risk_level'],
                    alert['source_ip'],
                    alert['destination_ip'],
                    alert['reason'],
                    alert['anomaly_score'],
                    alert['details']
                ])
        
        print(f"Saved {len(self.alerts)} alerts to {self.alert_file}")
    
    def print_alerts(self):
        """Print alerts in a formatted way."""
        if not self.alerts:
            print("No alerts generated.")
            return
        
        print("\n" + "="*80)
        print("SECURITY ALERTS")
        print("="*80)
        
        for alert in self.alerts:
            risk_symbol = {
                'HIGH': '[HIGH]',
                'MEDIUM': '[MEDIUM]', 
                'LOW': '[LOW]'
            }.get(alert['risk_level'], '[UNKNOWN]')
            
            print(f"\n{risk_symbol} ALERT: {alert['alert_type']} - {alert['risk_level']} RISK")
            print(f"   Source IP: {alert['source_ip']}")
            print(f"   Destination: {alert['destination_ip']}")
            print(f"   Reason: {alert['reason']}")
            print(f"   Anomaly Score: {alert['anomaly_score']:.3f}")
            print(f"   Details: {alert['details']}")
            print(f"   Time: {alert['timestamp']}")
            print("-" * 80)
    
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
                model_path = os.path.join(models_dir, f"{model_name}_{timestamp}.joblib")
                joblib.dump(model, model_path)
                print(f"Saved {model_name} model to: {model_path}")
            
            # Save scalers
            for scaler_name, scaler in self.scalers.items():
                scaler_path = os.path.join(models_dir, f"{scaler_name}_scaler_{timestamp}.joblib")
                joblib.dump(scaler, scaler_path)
                print(f"Saved {scaler_name} scaler to: {scaler_path}")
            
            # Save model metadata
            metadata = {
                'timestamp': timestamp,
                'models_trained': list(self.models.keys()),
                'scalers_trained': list(self.scalers.keys()),
                'feature_columns': [
                    'packet_count', 'avg_packet_size', 'max_packet_size', 'std_packet_size',
                    'unique_destinations', 'unique_dest_ports', 'avg_time_between_packets',
                    'total_bytes', 'protocol_diversity', 'duration_seconds',
                    'tcp_packets', 'udp_packets', 'icmp_packets',
                    'common_port_connections', 'high_port_connections',
                    'packets_per_second', 'bytes_per_second'
                ],
                'training_data_shape': self.features_df.shape if self.features_df is not None else None
            }
            
            metadata_path = os.path.join(models_dir, f"model_metadata_{timestamp}.json")
            import json
            with open(metadata_path, 'w') as f:
                json.dump(metadata, f, indent=2)
            print(f"Saved model metadata to: {metadata_path}")
            
            print(f"\nAll models saved successfully to '{models_dir}' directory!")
            
        except Exception as e:
            print(f"Error saving models: {e}")
    
    def load_models(self, timestamp: str = None):
        """Load previously trained models from disk."""
        models_dir = "data/trained_models"
        
        if not os.path.exists(models_dir):
            print(f"Models directory '{models_dir}' not found.")
            return False
        
        try:
            # Find the most recent models if timestamp not specified
            if timestamp is None:
                model_files = [f for f in os.listdir(models_dir) if f.endswith('.joblib') and 'scaler' not in f]
                if not model_files:
                    print("No model files found.")
                    return False
                
                # Extract timestamps and find the most recent
                timestamps = set()
                for file in model_files:
                    parts = file.split('_')
                    if len(parts) >= 2:
                        timestamps.add(parts[-1].replace('.joblib', ''))
                
                if not timestamps:
                    print("Could not extract timestamp from model files.")
                    return False
                
                timestamp = max(timestamps)
                print(f"Loading models with timestamp: {timestamp}")
            
            # Load models
            for model_name in ['isolation_forest', 'one_class_svm', 'local_outlier_factor']:
                model_path = os.path.join(models_dir, f"{model_name}_{timestamp}.joblib")
                if os.path.exists(model_path):
                    self.models[model_name] = joblib.load(model_path)
                    print(f"Loaded {model_name} model from: {model_path}")
            
            # Load scalers
            scaler_path = os.path.join(models_dir, f"standard_scaler_{timestamp}.joblib")
            if os.path.exists(scaler_path):
                self.scalers['standard'] = joblib.load(scaler_path)
                print(f"Loaded standard scaler from: {scaler_path}")
            
            # Load metadata
            metadata_path = os.path.join(models_dir, f"model_metadata_{timestamp}.json")
            if os.path.exists(metadata_path):
                import json
                with open(metadata_path, 'r') as f:
                    metadata = json.load(f)
                print(f"Loaded model metadata from: {metadata_path}")
                print(f"Models trained on: {metadata.get('timestamp', 'Unknown')}")
            
            print("Models loaded successfully!")
            return True
            
        except Exception as e:
            print(f"Error loading models: {e}")
            return False
    
    def generate_report(self):
        """Generate a comprehensive analysis report."""
        print("\n" + "="*80)
        print("NETWORK TRAFFIC ANALYSIS REPORT")
        print("="*80)
        
        print(f"Analysis Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Packet File: {self.packet_file}")
        print(f"Alert File: {self.alert_file}")
        
        if self.df is not None:
            print(f"\nData Summary:")
            print(f"  Total Packets Analyzed: {len(self.df)}")
            print(f"  Unique Source IPs: {self.df['source_ip'].nunique()}")
            print(f"  Unique Destination IPs: {self.df['destination_ip'].nunique()}")
            print(f"  Time Range: {self.df['timestamp'].min()} to {self.df['timestamp'].max()}")
        
        if self.features_df is not None:
            print(f"\nFeature Analysis:")
            print(f"  IPs Analyzed: {len(self.features_df)}")
            print(f"  Average Packets per IP: {self.features_df['packet_count'].mean():.2f}")
            print(f"  Average Destinations per IP: {self.features_df['unique_destinations'].mean():.2f}")
        
        print(f"\nSecurity Alerts:")
        print(f"  Total Alerts Generated: {len(self.alerts)}")
        
        if self.alerts:
            high_risk = len([a for a in self.alerts if a['risk_level'] == 'HIGH'])
            medium_risk = len([a for a in self.alerts if a['risk_level'] == 'MEDIUM'])
            low_risk = len([a for a in self.alerts if a['risk_level'] == 'LOW'])
            
            print(f"  High Risk: {high_risk}")
            print(f"  Medium Risk: {medium_risk}")
            print(f"  Low Risk: {low_risk}")
        
        print("="*80)


def main():
    """Main function to run the network traffic analyzer."""
    print("Network Traffic Analyzer - Part 2: Analysis and Detection")
    print("=" * 70)
    
    # Initialize analyzer
    analyzer = NetworkTrafficAnalyzer('data/packets_extended.csv')
    
    # Load and clean data
    if not analyzer.load_data():
        print("Failed to load packet data. Exiting.")
        return
    
    if not analyzer.clean_data():
        print("Failed to clean packet data. Exiting.")
        return
    
    # Perform analysis
    analyzer.exploratory_data_analysis()
    analyzer.feature_engineering()
    
    # Train models and detect anomalies
    if ML_AVAILABLE:
        analyzer.train_anomaly_models()
    
    alerts = analyzer.detect_anomalies()
    
    # Save and display results
    analyzer.save_alerts()
    analyzer.print_alerts()
    analyzer.generate_report()
    
    print(f"\nAnalysis complete! Check {analyzer.alert_file} for detailed alerts.")


if __name__ == "__main__":
    main()
