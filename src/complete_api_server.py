#!/usr/bin/env python3
"""
Complete Network Traffic Analyzer API Server
Integrates packet loading, ML models, and frontend
"""

import os
import sys
import pandas as pd
import json
import numpy as np
from datetime import datetime, timedelta
from flask import Flask, jsonify, request
from flask_cors import CORS
import joblib
from sklearn.preprocessing import StandardScaler

# Add src directory to path for ML modules
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'src'))

app = Flask(__name__)
CORS(app)

# Data file paths
DATA_DIR = os.path.join(os.path.dirname(__file__), '..', 'data')
PACKETS_FILE = os.path.join(DATA_DIR, 'packets_extended.csv')
ALERTS_FILE = os.path.join(DATA_DIR, 'alerts.csv')
STREAMING_ALERTS_FILE = os.path.join(DATA_DIR, 'streaming_alerts.csv')
MODELS_DIR = os.path.join(DATA_DIR, 'trained_models')

# Global variables for caching
packets_df = None
alerts_df = None
ml_models = {}
last_data_load = None

def load_ml_models():
    """Load trained ML models"""
    global ml_models
    
    try:
        # Look for the most recent model files
        model_files = []
        if os.path.exists(MODELS_DIR):
            for file in os.listdir(MODELS_DIR):
                if file.endswith('.joblib') and 'streaming' in file:
                    model_files.append(os.path.join(MODELS_DIR, file))
        
        if model_files:
            # Load the most recent streaming models
            for model_file in model_files:
                if 'isolation_forest' in model_file:
                    ml_models['isolation_forest'] = joblib.load(model_file)
                elif 'one_class_svm' in model_file:
                    ml_models['one_class_svm'] = joblib.load(model_file)
                elif 'local_outlier_factor' in model_file:
                    ml_models['lof'] = joblib.load(model_file)
                elif 'standard_scaler' in model_file:
                    ml_models['scaler'] = joblib.load(model_file)
            
            print(f"Loaded {len(ml_models)} ML models")
            return True
        else:
            print("No ML models found")
            return False
    except Exception as e:
        print(f"Error loading ML models: {e}")
        return False

def load_data():
    """Load and cache data from CSV files"""
    global packets_df, alerts_df, last_data_load
    
    try:
        # Load packets data
        if os.path.exists(PACKETS_FILE):
            packets_df = pd.read_csv(PACKETS_FILE)
            packets_df['timestamp'] = pd.to_datetime(packets_df['timestamp'])
            print(f"Loaded {len(packets_df)} packets")
        else:
            packets_df = pd.DataFrame()
            print("No packets file found")
        
        # Load alerts data
        alerts_df = pd.DataFrame()
        if os.path.exists(ALERTS_FILE):
            alerts_df = pd.read_csv(ALERTS_FILE)
            alerts_df['timestamp'] = pd.to_datetime(alerts_df['timestamp'])
            print(f"Loaded {len(alerts_df)} alerts")
        
        # Load streaming alerts if available
        if os.path.exists(STREAMING_ALERTS_FILE):
            streaming_alerts_df = pd.read_csv(STREAMING_ALERTS_FILE)
            streaming_alerts_df['timestamp'] = pd.to_datetime(streaming_alerts_df['timestamp'])
            alerts_df = pd.concat([alerts_df, streaming_alerts_df], ignore_index=True)
            print(f"Total alerts after adding streaming: {len(alerts_df)}")
        
        last_data_load = datetime.now()
        return True
    except Exception as e:
        print(f"Error loading data: {e}")
        return False

def extract_features(packet_data):
    """Extract features for ML model"""
    try:
        features = []
        
        # Basic features
        features.append(packet_data.get('packet_size', 0))
        features.append(packet_data.get('src_port', 0))
        features.append(packet_data.get('dst_port', 0))
        
        # Protocol encoding
        protocol_map = {'TCP': 1, 'UDP': 2, 'ICMP': 3, 'HTTP': 4, 'HTTPS': 5}
        features.append(protocol_map.get(packet_data.get('protocol', 'TCP'), 1))
        
        # IP address features (simplified)
        src_ip = packet_data.get('src_ip', '0.0.0.0')
        dst_ip = packet_data.get('dst_ip', '0.0.0.0')
        
        # Extract first octet as feature
        try:
            src_first_octet = int(src_ip.split('.')[0])
            dst_first_octet = int(dst_ip.split('.')[0])
        except:
            src_first_octet = 0
            dst_first_octet = 0
        
        features.extend([src_first_octet, dst_first_octet])
        
        return np.array(features).reshape(1, -1)
    except Exception as e:
        print(f"Error extracting features: {e}")
        return np.array([[0, 0, 0, 1, 0, 0]])

def predict_anomaly(packet_data):
    """Use ML models to predict if packet is anomalous"""
    try:
        if not ml_models:
            return False, 0.5
        
        features = extract_features(packet_data)
        
        # Scale features
        if 'scaler' in ml_models:
            features = ml_models['scaler'].transform(features)
        
        # Get predictions from all models
        predictions = []
        scores = []
        
        if 'isolation_forest' in ml_models:
            pred = ml_models['isolation_forest'].predict(features)[0]
            score = ml_models['isolation_forest'].decision_function(features)[0]
            predictions.append(pred == -1)  # -1 means anomaly
            scores.append(abs(score))
        
        if 'one_class_svm' in ml_models:
            pred = ml_models['one_class_svm'].predict(features)[0]
            score = ml_models['one_class_svm'].decision_function(features)[0]
            predictions.append(pred == -1)
            scores.append(abs(score))
        
        if 'lof' in ml_models:
            pred = ml_models['lof'].predict(features)[0]
            score = ml_models['lof'].decision_function(features)[0]
            predictions.append(pred == -1)
            scores.append(abs(score))
        
        # Majority vote
        is_anomaly = sum(predictions) > len(predictions) / 2
        avg_score = np.mean(scores) if scores else 0.5
        
        return is_anomaly, avg_score
    except Exception as e:
        print(f"Error in ML prediction: {e}")
        return False, 0.5

@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'message': 'Network Traffic Analyzer API is running',
        'models_loaded': len(ml_models),
        'data_loaded': packets_df is not None and not packets_df.empty
    })

@app.route('/api/stats', methods=['GET'])
def get_stats():
    """Get overall statistics"""
    global packets_df, alerts_df
    
    if packets_df is None or alerts_df is None:
        load_data()
    
    stats = {
        'total_packets': len(packets_df) if packets_df is not None else 0,
        'total_alerts': len(alerts_df) if alerts_df is not None else 0,
        'unique_devices': len(packets_df['src_ip'].unique()) if packets_df is not None and not packets_df.empty else 0,
        'unique_destinations': len(packets_df['dst_ip'].unique()) if packets_df is not None and not packets_df.empty else 0,
        'protocols': packets_df['protocol'].value_counts().to_dict() if packets_df is not None and not packets_df.empty else {},
        'high_risk_alerts': len(alerts_df[alerts_df['risk_level'] == 'High']) if alerts_df is not None and not alerts_df.empty else 0,
        'medium_risk_alerts': len(alerts_df[alerts_df['risk_level'] == 'Medium']) if alerts_df is not None and not alerts_df.empty else 0,
        'low_risk_alerts': len(alerts_df[alerts_df['risk_level'] == 'Low']) if alerts_df is not None and not alerts_df.empty else 0,
        'ml_models_loaded': len(ml_models),
        'last_updated': datetime.now().isoformat()
    }
    
    return jsonify(stats)

@app.route('/api/packets', methods=['GET'])
def get_packets():
    """Get packet data with optional filtering and ML analysis"""
    global packets_df
    
    if packets_df is None:
        load_data()
    
    # Get query parameters
    limit = request.args.get('limit', 100, type=int)
    protocol = request.args.get('protocol')
    src_ip = request.args.get('src_ip')
    analyze = request.args.get('analyze', 'false').lower() == 'true'
    
    # Apply filters
    filtered_df = packets_df.copy() if packets_df is not None else pd.DataFrame()
    if protocol:
        filtered_df = filtered_df[filtered_df['protocol'] == protocol]
    if src_ip:
        filtered_df = filtered_df[filtered_df['src_ip'] == src_ip]
    
    # Limit results
    filtered_df = filtered_df.tail(limit)
    
    # Convert to JSON-serializable format
    packets_data = filtered_df.to_dict('records')
    
    # Add ML analysis if requested
    if analyze and ml_models:
        for packet in packets_data:
            is_anomaly, score = predict_anomaly(packet)
            packet['ml_anomaly'] = is_anomaly
            packet['ml_score'] = round(score, 3)
    
    return jsonify({
        'packets': packets_data,
        'total': len(filtered_df),
        'filtered': len(packets_data),
        'ml_analysis': analyze and len(ml_models) > 0
    })

@app.route('/api/alerts', methods=['GET'])
def get_alerts():
    """Get alert data with optional filtering"""
    global alerts_df
    
    if alerts_df is None:
        load_data()
    
    # Get query parameters
    limit = request.args.get('limit', 100, type=int)
    risk_level = request.args.get('risk_level')
    recent_only = request.args.get('recent_only', 'false').lower() == 'true'
    
    # Apply filters
    filtered_df = alerts_df.copy() if alerts_df is not None else pd.DataFrame()
    if risk_level:
        filtered_df = filtered_df[filtered_df['risk_level'] == risk_level]
    if recent_only:
        cutoff_time = datetime.now() - timedelta(hours=24)
        filtered_df = filtered_df[filtered_df['timestamp'] >= cutoff_time]
    
    # Sort by timestamp (newest first)
    filtered_df = filtered_df.sort_values('timestamp', ascending=False)
    
    # Limit results
    filtered_df = filtered_df.head(limit)
    
    # Convert to JSON-serializable format
    alerts_data = filtered_df.to_dict('records')
    
    return jsonify({
        'alerts': alerts_data,
        'total': len(filtered_df),
        'filtered': len(alerts_data)
    })

@app.route('/api/traffic-over-time', methods=['GET'])
def get_traffic_over_time():
    """Get traffic data aggregated over time"""
    global packets_df
    
    if packets_df is None:
        load_data()
    
    if packets_df is None or packets_df.empty:
        return jsonify({'traffic': []})
    
    # Group by time intervals (every 5 minutes)
    packets_df['time_bucket'] = packets_df['timestamp'].dt.floor('5T')
    traffic_data = packets_df.groupby('time_bucket').agg({
        'packet_size': ['count', 'sum'],
        'src_ip': 'nunique'
    }).reset_index()
    
    traffic_data.columns = ['timestamp', 'packet_count', 'total_bytes', 'unique_ips']
    
    # Convert to JSON-serializable format
    traffic_records = traffic_data.to_dict('records')
    
    return jsonify({
        'traffic': traffic_records,
        'interval': '5 minutes'
    })

@app.route('/api/top-ips', methods=['GET'])
def get_top_ips():
    """Get top source IPs by traffic volume"""
    global packets_df
    
    if packets_df is None:
        load_data()
    
    if packets_df is None or packets_df.empty:
        return jsonify({'top_ips': []})
    
    # Group by source IP
    ip_stats = packets_df.groupby('src_ip').agg({
        'packet_size': ['count', 'sum'],
        'dst_ip': 'nunique'
    }).reset_index()
    
    ip_stats.columns = ['src_ip', 'packet_count', 'total_bytes', 'unique_destinations']
    
    # Sort by packet count
    ip_stats = ip_stats.sort_values('packet_count', ascending=False)
    
    # Limit to top 10
    top_ips = ip_stats.head(10).to_dict('records')
    
    return jsonify({
        'top_ips': top_ips
    })

@app.route('/api/protocol-distribution', methods=['GET'])
def get_protocol_distribution():
    """Get protocol distribution data"""
    global packets_df
    
    if packets_df is None:
        load_data()
    
    if packets_df is None or packets_df.empty:
        return jsonify({'protocols': []})
    
    # Count packets by protocol
    protocol_counts = packets_df['protocol'].value_counts().reset_index()
    protocol_counts.columns = ['protocol', 'count']
    
    # Calculate percentages
    total_packets = len(packets_df)
    protocol_counts['percentage'] = (protocol_counts['count'] / total_packets * 100).round(2)
    
    protocols = protocol_counts.to_dict('records')
    
    return jsonify({
        'protocols': protocols,
        'total_packets': total_packets
    })

@app.route('/api/ml-status', methods=['GET'])
def get_ml_status():
    """Get ML model status and information"""
    return jsonify({
        'models_loaded': len(ml_models),
        'available_models': list(ml_models.keys()),
        'models_dir': MODELS_DIR,
        'models_dir_exists': os.path.exists(MODELS_DIR)
    })

if __name__ == '__main__':
    print("Starting Network Traffic Analyzer API Server...")
    print("API will be available at: http://localhost:5000")
    print("Data directory:", DATA_DIR)
    print("Models directory:", MODELS_DIR)
    
    # Load ML models
    print("Loading ML models...")
    load_ml_models()
    
    # Load data
    print("Loading data...")
    load_data()
    
    print("Server ready!")
    print("Endpoints available:")
    print("  GET /api/health - Health check")
    print("  GET /api/stats - Overall statistics")
    print("  GET /api/packets - Packet data with ML analysis")
    print("  GET /api/alerts - Alert data")
    print("  GET /api/traffic-over-time - Traffic over time")
    print("  GET /api/top-ips - Top source IPs")
    print("  GET /api/protocol-distribution - Protocol distribution")
    print("  GET /api/ml-status - ML model status")
    
    app.run(host='0.0.0.0', port=5000, debug=True)
