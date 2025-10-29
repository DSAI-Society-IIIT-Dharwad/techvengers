#!/usr/bin/env python3
"""
Network Security Web Dashboard
A modern web application for real-time network monitoring with ML-powered anomaly detection
"""

from flask import Flask, render_template, jsonify, request
from flask_socketio import SocketIO, emit
import threading
import time
import json
import random
import numpy as np
from datetime import datetime, timedelta
from collections import deque
import queue
import warnings
warnings.filterwarnings('ignore')

# Import ML components from desktop app
import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# ML Manager (simplified for web)
class WebMLManager:
    """Web-optimized ML model manager"""
    
    def __init__(self):
        self.models = {}
        self.scalers = {}
        self.training_data = []
        self.is_trained = False
        self.min_samples_for_training = 500
        self.max_training_samples = 2000
        self.training_progress = 0
        self.last_training_time = None
        
    def add_training_sample(self, packet_data):
        """Add a packet to training data"""
        features = self.extract_features(packet_data)
        if features is not None:
            self.training_data.append(features.flatten())
            self.training_progress = min(100, (len(self.training_data) / self.min_samples_for_training) * 100)
            
            if len(self.training_data) > self.max_training_samples:
                self.training_data = self.training_data[-self.max_training_samples:]
    
    def extract_features(self, packet_data):
        """Extract features from packet data"""
        try:
            features = []
            features.append(packet_data.get('size', 0))
            features.append(packet_data.get('port', 0))
            
            protocol_map = {'TCP': 1, 'UDP': 2, 'ICMP': 3, 'HTTP': 4, 'HTTPS': 5}
            protocol = packet_data.get('protocol', 'TCP')
            features.append(protocol_map.get(protocol, 1))
            
            source_ip = packet_data.get('source', '192.168.1.1')
            dest_ip = packet_data.get('destination', '192.168.1.1')
            
            source_internal = 1 if source_ip.startswith(('192.168.', '10.', '172.')) else 0
            dest_internal = 1 if dest_ip.startswith(('192.168.', '10.', '172.')) else 0
            features.extend([source_internal, dest_internal])
            
            port = packet_data.get('port', 0)
            features.extend([
                1 if port < 1024 else 0,
                1 if 1024 <= port < 49152 else 0,
                1 if port >= 49152 else 0
            ])
            
            size = packet_data.get('size', 0)
            features.extend([
                1 if size < 64 else 0,
                1 if 64 <= size < 512 else 0,
                1 if size >= 512 else 0
            ])
            
            while len(features) < 10:
                features.append(0)
                
            return np.array(features[:10]).reshape(1, -1)
            
        except Exception as e:
            print(f"Error extracting features: {e}")
            return np.zeros((1, 10))
    
    def train_models(self):
        """Train ML models on collected data"""
        if len(self.training_data) < self.min_samples_for_training:
            return False
        
        try:
            from sklearn.preprocessing import StandardScaler
            from sklearn.ensemble import IsolationForest
            from sklearn.svm import OneClassSVM
            
            X = np.array(self.training_data)
            
            self.scalers['standard'] = StandardScaler()
            X_scaled = self.scalers['standard'].fit_transform(X)
            
            self.models['isolation_forest'] = IsolationForest(
                contamination=0.1, random_state=42, n_estimators=100
            )
            self.models['isolation_forest'].fit(X_scaled)
            
            self.models['one_class_svm'] = OneClassSVM(
                nu=0.1, kernel='rbf', gamma='scale'
            )
            self.models['one_class_svm'].fit(X_scaled)
            
            self.is_trained = True
            self.last_training_time = datetime.now()
            print(f"Web ML models trained on {len(self.training_data)} samples")
            return True
            
        except Exception as e:
            print(f"Training error: {e}")
            return False
    
    def predict_anomaly(self, packet_data):
        """Predict if packet is anomalous"""
        try:
            if not self.is_trained:
                return {'is_anomaly': False, 'confidence': 0.5, 'model': 'training'}
            
            features = self.extract_features(packet_data)
            
            if 'standard' in self.scalers:
                features_scaled = self.scalers['standard'].transform(features)
            else:
                features_scaled = features
            
            predictions = {}
            confidences = {}
            
            for model_name, model in self.models.items():
                try:
                    if model_name == 'one_class_svm' and hasattr(model, 'decision_function'):
                        score = model.decision_function(features_scaled)[0]
                        prediction = score < 0
                        confidence = abs(score)
                    elif model_name == 'isolation_forest' and hasattr(model, 'score_samples'):
                        score = model.score_samples(features_scaled)[0]
                        prediction = score < -0.1
                        confidence = abs(score)
                    else:
                        prediction = False
                        confidence = 0.5
                    
                    predictions[model_name] = prediction
                    confidences[model_name] = confidence
                    
                except Exception as e:
                    print(f"Error with {model_name}: {e}")
                    predictions[model_name] = False
                    confidences[model_name] = 0.5
            
            anomaly_votes = sum(predictions.values())
            is_anomaly = anomaly_votes > len(predictions) / 2
            avg_confidence = np.mean(list(confidences.values()))
            
            return {
                'is_anomaly': bool(is_anomaly),
                'confidence': float(avg_confidence),
                'model_predictions': predictions,
                'model_confidences': confidences,
                'features_used': len(features[0]),
                'training_samples': len(self.training_data)
            }
            
        except Exception as e:
            print(f"Error in prediction: {e}")
            return {'is_anomaly': False, 'confidence': 0.5, 'error': str(e)}
    
    def get_training_status(self):
        """Get current training status"""
        return {
            'is_trained': self.is_trained,
            'training_samples': len(self.training_data),
            'min_samples_needed': self.min_samples_for_training,
            'models_available': list(self.models.keys()),
            'training_progress': self.training_progress,
            'last_training_time': self.last_training_time
        }

# Network Monitor (simplified for web)
class WebNetworkMonitor:
    """Web-optimized network packet monitoring"""
    
    def __init__(self, ml_manager):
        self.ml_manager = ml_manager
        self.is_monitoring = False
        self.packet_count = 0
        self.device_set = set()
        self.device_info = {}
        self.bandwidth_usage = {}
        self.packets = deque(maxlen=1000)
        self.alerts = deque(maxlen=100)
        self.threats = deque(maxlen=50)
        
    def start_monitoring(self):
        """Start network monitoring"""
        self.is_monitoring = True
        self.packet_count = 0
        self.device_set.clear()
        self.device_info.clear()
        self.bandwidth_usage.clear()
        
    def stop_monitoring(self):
        """Stop network monitoring"""
        self.is_monitoring = False
        
    def generate_packet(self):
        """Generate simulated network packet"""
        protocols = ['TCP', 'UDP', 'ICMP', 'HTTP', 'HTTPS']
        sources = [f"192.168.1.{i}" for i in range(1, 255)]
        destinations = [f"10.0.0.{i}" for i in range(1, 255)]
        external_ips = ['8.8.8.8', '1.1.1.1', '208.67.222.222', '9.9.9.9']
        destinations.extend(external_ips)
        
        protocol = random.choice(protocols)
        source_ip = random.choice(sources)
        dest_ip = random.choice(destinations)
        
        mac_address = ':'.join([f"{random.randint(0, 255):02x}" for _ in range(6)])
        device_type = self.get_device_type(source_ip)
        
        packet = {
            'id': self.packet_count,
            'timestamp': datetime.now(),
            'source': source_ip,
            'destination': dest_ip,
            'protocol': protocol,
            'port': random.randint(1, 65535),
            'size': random.randint(64, 1500),
            'protocol_num': {'TCP': 1, 'UDP': 2, 'ICMP': 3, 'HTTP': 4, 'HTTPS': 5}[protocol],
            'flags': random.randint(0, 15),
            'mac_address': mac_address,
            'device_type': device_type,
            'connection_status': 'active'
        }
        
        self.packet_count += 1
        self.device_set.add(source_ip)
        self.device_set.add(dest_ip)
        
        self.update_device_info(source_ip, packet)
        self.update_device_info(dest_ip, packet)
        self.update_bandwidth_usage(source_ip, packet['size'])
        
        self.ml_manager.add_training_sample(packet)
        
        if len(self.ml_manager.training_data) >= self.ml_manager.min_samples_for_training and not self.ml_manager.is_trained:
            self.ml_manager.train_models()
        
        return packet
    
    def get_device_type(self, ip):
        """Determine device type based on IP address"""
        if ip.startswith('192.168.1.'):
            last_octet = int(ip.split('.')[-1])
            if last_octet < 10:
                return 'Router/Gateway'
            elif last_octet < 50:
                return 'Server'
            elif last_octet < 100:
                return 'Desktop'
            elif last_octet < 150:
                return 'Laptop'
            elif last_octet < 200:
                return 'Mobile Device'
            else:
                return 'IoT Device'
        elif ip.startswith('10.0.0.'):
            return 'External Server'
        else:
            return 'External Device'
    
    def update_device_info(self, ip, packet):
        """Update device information"""
        if ip not in self.device_info:
            self.device_info[ip] = {
                'first_seen': packet['timestamp'],
                'last_seen': packet['timestamp'],
                'packet_count': 0,
                'total_bytes': 0,
                'protocols': set(),
                'ports': set(),
                'device_type': packet.get('device_type', 'Unknown'),
                'mac_address': packet.get('mac_address', 'Unknown'),
                'connection_status': 'active'
            }
        
        device = self.device_info[ip]
        device['last_seen'] = packet['timestamp']
        device['packet_count'] += 1
        device['total_bytes'] += packet['size']
        device['protocols'].add(packet['protocol'])
        device['ports'].add(packet['port'])
    
    def update_bandwidth_usage(self, ip, size):
        """Update bandwidth usage statistics"""
        if ip not in self.bandwidth_usage:
            self.bandwidth_usage[ip] = {
                'bytes_sent': 0,
                'bytes_received': 0,
                'packets_sent': 0,
                'packets_received': 0
            }
        
        if ip.startswith(('192.168.', '10.', '172.')):
            self.bandwidth_usage[ip]['bytes_sent'] += size
            self.bandwidth_usage[ip]['packets_sent'] += 1
        else:
            self.bandwidth_usage[ip]['bytes_received'] += size
            self.bandwidth_usage[ip]['packets_received'] += 1

# Flask Application
app = Flask(__name__)
app.config['SECRET_KEY'] = 'network_security_dashboard_2024'
socketio = SocketIO(app, cors_allowed_origins="*")

# Global instances
ml_manager = WebMLManager()
network_monitor = WebNetworkMonitor(ml_manager)

# Monitoring thread
monitoring_thread = None
monitoring_active = False

def monitoring_loop():
    """Main monitoring loop for web app"""
    global monitoring_active
    while monitoring_active:
        if network_monitor.is_monitoring:
            packet = network_monitor.generate_packet()
            
            # Get ML prediction
            ml_prediction = ml_manager.predict_anomaly(packet)
            packet['ml_prediction'] = ml_prediction
            
            # Add to data storage
            network_monitor.packets.append(packet)
            
            # Check for anomalies
            if packet['ml_prediction']['is_anomaly'] and packet['ml_prediction']['confidence'] > 0.7:
                alert = {
                    'timestamp': packet['timestamp'],
                    'type': 'ML Anomaly Detected',
                    'severity': 'High' if packet['ml_prediction']['confidence'] > 0.9 else 'Medium',
                    'description': f"Anomalous packet detected ({packet['ml_prediction']['confidence']:.1%} confidence)",
                    'source': packet['source'],
                    'destination': packet['destination'],
                    'protocol': packet['protocol'],
                    'confidence': packet['ml_prediction']['confidence']
                }
                network_monitor.alerts.append(alert)
                
                if packet['ml_prediction']['confidence'] > 0.8:
                    threat = {
                        'timestamp': packet['timestamp'],
                        'type': 'High Confidence Threat',
                        'source': packet['source'],
                        'destination': packet['destination'],
                        'confidence': packet['ml_prediction']['confidence'],
                        'description': f"High-risk anomaly detected by ML models"
                    }
                    network_monitor.threats.append(threat)
            
            # Emit real-time data to web clients
            socketio.emit('packet_data', {
                'packet': {
                    'id': packet['id'],
                    'timestamp': packet['timestamp'].isoformat(),
                    'source': packet['source'],
                    'destination': packet['destination'],
                    'protocol': packet['protocol'],
                    'port': packet['port'],
                    'size': packet['size'],
                    'device_type': packet['device_type'],
                    'mac_address': packet['mac_address']
                },
                'ml_prediction': packet['ml_prediction'],
                'stats': {
                    'total_packets': network_monitor.packet_count,
                    'active_devices': len(network_monitor.device_set),
                    'alerts': len(network_monitor.alerts),
                    'threats': len(network_monitor.threats),
                    'training_status': ml_manager.get_training_status()
                }
            })
            
            time.sleep(0.5)
        else:
            time.sleep(1)

@app.route('/')
def index():
    """Main dashboard page"""
    return render_template('dashboard.html')

@app.route('/api/stats')
def get_stats():
    """Get current statistics"""
    training_status = ml_manager.get_training_status()
    
    stats = {
        'total_packets': network_monitor.packet_count,
        'active_devices': len(network_monitor.device_set),
        'alerts': len(network_monitor.alerts),
        'threats': len(network_monitor.threats),
        'training_status': training_status,
        'monitoring_active': network_monitor.is_monitoring
    }
    
    return jsonify(stats)

@app.route('/api/devices')
def get_devices():
    """Get device information"""
    devices = []
    for ip, info in network_monitor.device_info.items():
        bandwidth = network_monitor.bandwidth_usage.get(ip, {})
        total_bytes = bandwidth.get('bytes_sent', 0) + bandwidth.get('bytes_received', 0)
        
        devices.append({
            'ip': ip,
            'device_type': info.get('device_type', 'Unknown'),
            'mac_address': info.get('mac_address', 'Unknown'),
            'status': info.get('connection_status', 'Unknown'),
            'packet_count': info.get('packet_count', 0),
            'bandwidth': f"{total_bytes // 1024} KB",
            'first_seen': info.get('first_seen', datetime.now()).isoformat(),
            'last_seen': info.get('last_seen', datetime.now()).isoformat(),
            'protocols': list(info.get('protocols', set())),
            'ports': list(info.get('ports', set()))[:10]
        })
    
    return jsonify(devices)

@app.route('/api/alerts')
def get_alerts():
    """Get recent alerts"""
    alerts = []
    for alert in list(network_monitor.alerts)[-20:]:
        alerts.append({
            'timestamp': alert['timestamp'].isoformat(),
            'type': alert['type'],
            'severity': alert['severity'],
            'description': alert['description'],
            'source': alert.get('source', 'Unknown'),
            'destination': alert.get('destination', 'Unknown'),
            'protocol': alert.get('protocol', 'Unknown'),
            'confidence': alert.get('confidence', 0)
        })
    
    return jsonify(alerts)

@app.route('/api/threats')
def get_threats():
    """Get recent threats"""
    threats = []
    for threat in list(network_monitor.threats)[-20:]:
        threats.append({
            'timestamp': threat['timestamp'].isoformat(),
            'type': threat['type'],
            'source': threat.get('source', 'Unknown'),
            'destination': threat.get('destination', 'Unknown'),
            'confidence': threat.get('confidence', 0),
            'description': threat.get('description', 'Unknown')
        })
    
    return jsonify(threats)

@app.route('/api/start_monitoring', methods=['POST'])
def start_monitoring():
    """Start network monitoring"""
    global monitoring_thread, monitoring_active
    
    if not monitoring_active:
        monitoring_active = True
        network_monitor.start_monitoring()
        
        monitoring_thread = threading.Thread(target=monitoring_loop, daemon=True)
        monitoring_thread.start()
        
        return jsonify({'status': 'started', 'message': 'Monitoring started successfully'})
    else:
        return jsonify({'status': 'already_running', 'message': 'Monitoring is already active'})

@app.route('/api/stop_monitoring', methods=['POST'])
def stop_monitoring():
    """Stop network monitoring"""
    global monitoring_active
    
    if monitoring_active:
        monitoring_active = False
        network_monitor.stop_monitoring()
        
        return jsonify({'status': 'stopped', 'message': 'Monitoring stopped successfully'})
    else:
        return jsonify({'status': 'not_running', 'message': 'Monitoring is not active'})

@app.route('/api/inject_threat', methods=['POST'])
def inject_threat():
    """Inject a test threat"""
    data = request.get_json()
    threat_type = data.get('type', 'ddos')
    
    # Generate threat packet
    threat_packet = {
        'id': f"threat_{network_monitor.packet_count}",
        'timestamp': datetime.now(),
        'source': f"192.168.1.{random.randint(200, 254)}",
        'destination': '192.168.1.1',
        'protocol': 'UDP',
        'port': random.randint(49152, 65535),
        'size': random.randint(1500, 2000),
        'protocol_num': 2,
        'flags': 0,
        'threat_type': threat_type
    }
    
    # Add to ML system
    ml_manager.add_training_sample(threat_packet)
    result = ml_manager.predict_anomaly(threat_packet)
    
    # Add to monitoring data
    network_monitor.packets.append(threat_packet)
    
    return jsonify({
        'status': 'injected',
        'threat_type': threat_type,
        'detected': result['is_anomaly'],
        'confidence': result['confidence'],
        'packet': threat_packet
    })

if __name__ == '__main__':
    print("Starting Network Security Web Dashboard...")
    print("Web interface will be available at: http://localhost:5000")
    socketio.run(app, debug=True, host='0.0.0.0', port=5000)
