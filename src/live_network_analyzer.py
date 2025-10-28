#!/usr/bin/env python3
"""
Live Network Traffic Analyzer with ML Integration
Processes real network traffic through trained ML models
"""

import os
import sys
import pandas as pd
import numpy as np
import json
import time
import threading
import queue
from datetime import datetime, timedelta
from flask import Flask, jsonify, request
from flask_cors import CORS
import joblib
from sklearn.preprocessing import StandardScaler
import psutil
import socket
import struct

# Add src directory to path
sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

app = Flask(__name__)
CORS(app)

# Data file paths
DATA_DIR = os.path.join(os.path.dirname(__file__), 'data')
PACKETS_FILE = os.path.join(DATA_DIR, 'packets_extended.csv')
ALERTS_FILE = os.path.join(DATA_DIR, 'alerts.csv')
STREAMING_ALERTS_FILE = os.path.join(DATA_DIR, 'streaming_alerts.csv')
MODELS_DIR = os.path.join(DATA_DIR, 'trained_models')

# Global variables
packets_df = None
alerts_df = None
ml_models = {}
live_packets = []
live_alerts = []
packet_queue = queue.Queue()
is_capturing = False
capture_thread = None

def load_ml_models():
    """Load trained ML models"""
    global ml_models
    
    try:
        if not os.path.exists(MODELS_DIR):
            print(f"Models directory not found: {MODELS_DIR}")
            return False
            
        model_files = []
        for file in os.listdir(MODELS_DIR):
            if file.endswith('.joblib'):
                model_files.append(os.path.join(MODELS_DIR, file))
        
        if not model_files:
            print("No ML model files found")
            return False
        
        # Load models
        for model_file in model_files:
            if 'isolation_forest' in model_file:
                ml_models['isolation_forest'] = joblib.load(model_file)
                print(f"Loaded Isolation Forest model")
            elif 'one_class_svm' in model_file:
                ml_models['one_class_svm'] = joblib.load(model_file)
                print(f"Loaded One-Class SVM model")
            elif 'local_outlier_factor' in model_file:
                ml_models['lof'] = joblib.load(model_file)
                print(f"Loaded LOF model")
            elif 'standard_scaler' in model_file:
                ml_models['scaler'] = joblib.load(model_file)
                print(f"Loaded Standard Scaler")
        
        print(f"Successfully loaded {len(ml_models)} ML models")
        return len(ml_models) > 0
    except Exception as e:
        print(f"Error loading ML models: {e}")
        return False

def load_historical_data():
    """Load historical data for baseline"""
    global packets_df, alerts_df
    
    try:
        # Load packets data
        if os.path.exists(PACKETS_FILE):
            packets_df = pd.read_csv(PACKETS_FILE)
            packets_df['timestamp'] = pd.to_datetime(packets_df['timestamp'])
            print(f"Loaded {len(packets_df)} historical packets")
        else:
            packets_df = pd.DataFrame()
            print("No historical packets file found")
        
        # Load alerts data
        alerts_df = pd.DataFrame()
        if os.path.exists(ALERTS_FILE):
            alerts_df = pd.read_csv(ALERTS_FILE)
            if 'timestamp' in alerts_df.columns:
                alerts_df['timestamp'] = pd.to_datetime(alerts_df['timestamp'])
            print(f"Loaded {len(alerts_df)} historical alerts")
        
        return True
    except Exception as e:
        print(f"Error loading historical data: {e}")
        return False

def extract_features_from_packet(packet_info):
    """Extract features from packet for ML analysis"""
    try:
        features = []
        
        # Basic features
        features.append(packet_info.get('packet_size', 0))
        features.append(packet_info.get('src_port', 0))
        features.append(packet_info.get('dst_port', 0))
        
        # Protocol encoding
        protocol_map = {'TCP': 1, 'UDP': 2, 'ICMP': 3, 'HTTP': 4, 'HTTPS': 5}
        features.append(protocol_map.get(packet_info.get('protocol', 'TCP'), 1))
        
        # IP address features
        src_ip = packet_info.get('src_ip', '0.0.0.0')
        dst_ip = packet_info.get('dst_ip', '0.0.0.0')
        
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

def predict_anomaly(packet_info):
    """Use ML models to predict if packet is anomalous"""
    try:
        if not ml_models:
            return False, 0.5, "No ML models loaded"
        
        features = extract_features_from_packet(packet_info)
        
        # Scale features
        if 'scaler' in ml_models:
            features = ml_models['scaler'].transform(features)
        
        # Get predictions from all models
        predictions = []
        scores = []
        model_names = []
        
        if 'isolation_forest' in ml_models:
            pred = ml_models['isolation_forest'].predict(features)[0]
            score = ml_models['isolation_forest'].decision_function(features)[0]
            predictions.append(pred == -1)  # -1 means anomaly
            scores.append(abs(score))
            model_names.append("Isolation Forest")
        
        if 'one_class_svm' in ml_models:
            pred = ml_models['one_class_svm'].predict(features)[0]
            score = ml_models['one_class_svm'].decision_function(features)[0]
            predictions.append(pred == -1)
            scores.append(abs(score))
            model_names.append("One-Class SVM")
        
        if 'lof' in ml_models:
            pred = ml_models['lof'].predict(features)[0]
            score = ml_models['lof'].decision_function(features)[0]
            predictions.append(pred == -1)
            scores.append(abs(score))
            model_names.append("LOF")
        
        # Majority vote
        is_anomaly = sum(predictions) > len(predictions) / 2
        avg_score = np.mean(scores) if scores else 0.5
        
        # Determine risk level
        if avg_score > 0.8:
            risk_level = "High"
        elif avg_score > 0.5:
            risk_level = "Medium"
        else:
            risk_level = "Low"
        
        return is_anomaly, avg_score, f"{', '.join(model_names)}: {risk_level}"
    except Exception as e:
        print(f"Error in ML prediction: {e}")
        return False, 0.5, f"Error: {str(e)}"

def get_network_connections():
    """Get current network connections using psutil"""
    try:
        connections = psutil.net_connections(kind='inet')
        packets = []
        
        for conn in connections:
            if conn.status == 'ESTABLISHED' and conn.laddr and conn.raddr:
                packet_info = {
                    'timestamp': datetime.now().isoformat(),
                    'src_ip': conn.laddr.ip,
                    'src_port': conn.laddr.port,
                    'dst_ip': conn.raddr.ip,
                    'dst_port': conn.raddr.port,
                    'protocol': 'TCP',  # psutil doesn't distinguish protocols easily
                    'packet_size': 0,  # Not available from psutil
                    'connection_status': conn.status
                }
                packets.append(packet_info)
        
        return packets
    except Exception as e:
        print(f"Error getting network connections: {e}")
        return []

def capture_live_traffic():
    """Capture live network traffic and analyze with ML"""
    global is_capturing, live_packets, live_alerts
    
    print("Starting live network traffic capture...")
    
    while is_capturing:
        try:
            # Get current network connections
            connections = get_network_connections()
            
            for conn in connections:
                # Analyze with ML models
                is_anomaly, score, details = predict_anomaly(conn)
                
                # Add to live packets
                conn['ml_anomaly'] = is_anomaly
                conn['ml_score'] = round(score, 3)
                conn['ml_details'] = details
                
                live_packets.append(conn)
                
                # If anomaly detected, create alert
                if is_anomaly:
                    alert = {
                        'timestamp': conn['timestamp'],
                        'src_ip': conn['src_ip'],
                        'dst_ip': conn['dst_ip'],
                        'protocol': conn['protocol'],
                        'src_port': conn['src_port'],
                        'dst_port': conn['dst_port'],
                        'reason': f"ML Anomaly Detection (Score: {score:.3f})",
                        'risk_level': 'High' if score > 0.8 else 'Medium' if score > 0.5 else 'Low',
                        'details': details,
                        'ml_score': score
                    }
                    live_alerts.append(alert)
                    print(f"ALERT: {alert['src_ip']} -> {alert['dst_ip']} ({alert['reason']})")
            
            # Keep only recent data (last 1000 packets)
            if len(live_packets) > 1000:
                live_packets = live_packets[-1000:]
            
            if len(live_alerts) > 100:
                live_alerts = live_alerts[-100:]
            
            time.sleep(2)  # Capture every 2 seconds
            
        except Exception as e:
            print(f"Error in live capture: {e}")
            time.sleep(5)

def start_live_capture():
    """Start live network traffic capture"""
    global is_capturing, capture_thread
    
    if not is_capturing:
        is_capturing = True
        capture_thread = threading.Thread(target=capture_live_traffic, daemon=True)
        capture_thread.start()
        print("Live network capture started")
        return True
    return False

def stop_live_capture():
    """Stop live network traffic capture"""
    global is_capturing
    
    if is_capturing:
        is_capturing = False
        print("Live network capture stopped")
        return True
    return False

# Flask API Endpoints

@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'message': 'Live Network Traffic Analyzer API is running',
        'models_loaded': len(ml_models),
        'live_capture': is_capturing,
        'live_packets': len(live_packets),
        'live_alerts': len(live_alerts)
    })

@app.route('/api/stats', methods=['GET'])
def get_stats():
    """Get overall statistics"""
    global packets_df, alerts_df, live_packets, live_alerts
    
    # Combine historical and live data
    total_packets = len(packets_df) if packets_df is not None else 0
    total_packets += len(live_packets)
    
    total_alerts = len(alerts_df) if alerts_df is not None else 0
    total_alerts += len(live_alerts)
    
    # Get unique devices from live packets
    unique_devices = set()
    if live_packets:
        for packet in live_packets:
            unique_devices.add(packet['src_ip'])
    
    # Add historical unique devices
    if packets_df is not None and not packets_df.empty:
        unique_devices.update(packets_df['src_ip'].unique())
    
    # Count risk levels from live alerts
    high_risk = len([a for a in live_alerts if a.get('risk_level') == 'High'])
    medium_risk = len([a for a in live_alerts if a.get('risk_level') == 'Medium'])
    low_risk = len([a for a in live_alerts if a.get('risk_level') == 'Low'])
    
    stats = {
        'total_packets': total_packets,
        'total_alerts': total_alerts,
        'unique_devices': len(unique_devices),
        'live_packets': len(live_packets),
        'live_alerts': len(live_alerts),
        'high_risk_alerts': high_risk,
        'medium_risk_alerts': medium_risk,
        'low_risk_alerts': low_risk,
        'ml_models_loaded': len(ml_models),
        'live_capture_active': is_capturing,
        'last_updated': datetime.now().isoformat()
    }
    
    return jsonify(stats)

@app.route('/api/live-packets', methods=['GET'])
def get_live_packets():
    """Get live packet data"""
    limit = request.args.get('limit', 50, type=int)
    
    recent_packets = live_packets[-limit:] if live_packets else []
    
    return jsonify({
        'packets': recent_packets,
        'total': len(live_packets),
        'live_capture': is_capturing
    })

@app.route('/api/live-alerts', methods=['GET'])
def get_live_alerts():
    """Get live alert data"""
    limit = request.args.get('limit', 20, type=int)
    
    recent_alerts = live_alerts[-limit:] if live_alerts else []
    
    return jsonify({
        'alerts': recent_alerts,
        'total': len(live_alerts),
        'live_capture': is_capturing
    })

@app.route('/api/start-capture', methods=['POST'])
def start_capture():
    """Start live network capture"""
    if start_live_capture():
        return jsonify({'status': 'success', 'message': 'Live capture started'})
    else:
        return jsonify({'status': 'error', 'message': 'Capture already running'})

@app.route('/api/stop-capture', methods=['POST'])
def stop_capture():
    """Stop live network capture"""
    if stop_live_capture():
        return jsonify({'status': 'success', 'message': 'Live capture stopped'})
    else:
        return jsonify({'status': 'error', 'message': 'Capture not running'})

@app.route('/api/traffic-over-time', methods=['GET'])
def get_traffic_over_time():
    """Get traffic data over time"""
    # Generate sample data for demo
    now = datetime.now()
    traffic_data = []
    
    for i in range(12):
        time_point = now - timedelta(minutes=i*5)
        packet_count = len([p for p in live_packets 
                          if datetime.fromisoformat(p['timestamp'].replace('Z', '+00:00')) > time_point])
        
        traffic_data.append({
            'timestamp': time_point.isoformat(),
            'packet_count': packet_count + np.random.randint(10, 50),
            'unique_ips': len(set(p['src_ip'] for p in live_packets 
                                if datetime.fromisoformat(p['timestamp'].replace('Z', '+00:00')) > time_point))
        })
    
    return jsonify({
        'traffic': list(reversed(traffic_data)),
        'interval': '5 minutes'
    })

@app.route('/api/protocol-distribution', methods=['GET'])
def get_protocol_distribution():
    """Get protocol distribution"""
    protocols = {}
    
    for packet in live_packets:
        protocol = packet.get('protocol', 'Unknown')
        protocols[protocol] = protocols.get(protocol, 0) + 1
    
    # Add some demo data if no live data
    if not protocols:
        protocols = {'TCP': 45, 'UDP': 25, 'ICMP': 15, 'HTTP': 10, 'HTTPS': 5}
    
    total = sum(protocols.values())
    protocol_data = []
    
    for protocol, count in protocols.items():
        protocol_data.append({
            'protocol': protocol,
            'count': count,
            'percentage': round(count / total * 100, 2) if total > 0 else 0
        })
    
    return jsonify({
        'protocols': protocol_data,
        'total_packets': total
    })

@app.route('/api/top-ips', methods=['GET'])
def get_top_ips():
    """Get top source IPs"""
    ip_counts = {}
    
    for packet in live_packets:
        src_ip = packet.get('src_ip', 'Unknown')
        ip_counts[src_ip] = ip_counts.get(src_ip, 0) + 1
    
    # Add some demo data if no live data
    if not ip_counts:
        ip_counts = {
            '192.168.1.1': 120,
            '192.168.1.2': 95,
            '10.0.0.1': 80,
            '172.16.0.1': 65,
            '192.168.0.1': 50
        }
    
    top_ips = []
    for src_ip, count in sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:10]:
        top_ips.append({
            'src_ip': src_ip,
            'packet_count': count,
            'total_bytes': count * 64,  # Estimate
            'unique_destinations': len(set(p['dst_ip'] for p in live_packets if p.get('src_ip') == src_ip))
        })
    
    return jsonify({
        'top_ips': top_ips
    })

if __name__ == '__main__':
    print("Starting Live Network Traffic Analyzer with ML Integration...")
    print("API will be available at: http://localhost:5000")
    print("Data directory:", DATA_DIR)
    print("Models directory:", MODELS_DIR)
    
    # Load ML models
    print("\nLoading ML models...")
    models_loaded = load_ml_models()
    
    # Load historical data
    print("\nLoading historical data...")
    load_historical_data()
    
    # Start live capture automatically
    print("\nStarting live network capture...")
    start_live_capture()
    
    print("\nServer ready!")
    print("Endpoints available:")
    print("  GET /api/health - Health check")
    print("  GET /api/stats - Overall statistics")
    print("  GET /api/live-packets - Live packet data")
    print("  GET /api/live-alerts - Live alert data")
    print("  POST /api/start-capture - Start live capture")
    print("  POST /api/stop-capture - Stop live capture")
    print("  GET /api/traffic-over-time - Traffic over time")
    print("  GET /api/top-ips - Top source IPs")
    print("  GET /api/protocol-distribution - Protocol distribution")
    
    app.run(host='0.0.0.0', port=5000, debug=True)
