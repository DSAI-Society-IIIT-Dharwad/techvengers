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

# Import real packet sniffer
try:
    from real_packet_sniffer import RealPacketSniffer
    REAL_PACKET_CAPTURE_AVAILABLE = True
except ImportError as e:
    print(f"Real packet capture not available: {e}")
    REAL_PACKET_CAPTURE_AVAILABLE = False

# ML Manager (simplified for web)
class WebMLManager:
    """Web-optimized ML model manager with persistent data"""
    
    def __init__(self):
        self.models = {}
        self.scalers = {}
        self.training_data = []
        self.is_trained = False
        self.min_samples_for_training = 50  # Reduced for faster ML training with real packets
        self.max_training_samples = 2000
        self.training_progress = 0
        self.last_training_time = None
        
        # Load persistent data
        self.load_persistent_data()
        
    def save_persistent_data(self):
        """Save training data to prevent loss on restart"""
        try:
            import pickle
            import os
            
            # Create data directory if it doesn't exist
            data_dir = '../data'
            if not os.path.exists(data_dir):
                os.makedirs(data_dir)
            
            # Save training data
            persistent_data = {
                'training_data': self.training_data,
                'is_trained': self.is_trained,
                'training_progress': self.training_progress,
                'last_training_time': self.last_training_time,
                'min_samples_for_training': self.min_samples_for_training
            }
            
            with open(f'{data_dir}/web_ml_data.pkl', 'wb') as f:
                pickle.dump(persistent_data, f)
                
        except Exception as e:
            print(f"Error saving persistent data: {e}")
    
    def load_persistent_data(self):
        """Load training data from previous sessions"""
        try:
            import pickle
            import os
            
            data_file = '../data/web_ml_data.pkl'
            if os.path.exists(data_file):
                with open(data_file, 'rb') as f:
                    persistent_data = pickle.load(f)
                
                self.training_data = persistent_data.get('training_data', [])
                self.is_trained = persistent_data.get('is_trained', False)
                self.training_progress = persistent_data.get('training_progress', 0)
                self.last_training_time = persistent_data.get('last_training_time', None)
                
                print(f"Loaded persistent ML data: {len(self.training_data)} samples, trained: {self.is_trained}")
            else:
                print("No persistent ML data found, starting fresh")
                
        except Exception as e:
            print(f"Error loading persistent data: {e}")
            self.training_data = []
            self.is_trained = False
            self.training_progress = 0
            self.last_training_time = None
        
    def add_training_sample(self, packet_data):
        """Add a packet to training data"""
        features = self.extract_features(packet_data)
        if features is not None:
            self.training_data.append(features.flatten())
            self.training_progress = min(100, (len(self.training_data) / self.min_samples_for_training) * 100)
            
            # Debug output for ML training progress
            if len(self.training_data) % 10 == 0:  # Print every 10 samples
                print(f"ML Training Progress: {len(self.training_data)}/{self.min_samples_for_training} samples ({self.training_progress:.1f}%)")
            
            if len(self.training_data) > self.max_training_samples:
                self.training_data = self.training_data[-self.max_training_samples:]
            
            # Save data every 25 samples to prevent loss
            if len(self.training_data) % 25 == 0:
                self.save_persistent_data()
    
    def extract_features(self, packet_data):
        """Extract features from real packet data"""
        try:
            features = []
            
            # Basic packet features
            features.append(packet_data.get('size', 0))
            features.append(packet_data.get('src_port', 0))
            
            # Protocol mapping for real packets
            protocol_map = {'TCP': 1, 'UDP': 2, 'ICMP': 3, 'ARP': 4, 'Unknown': 5}
            protocol = packet_data.get('protocol_name', 'Unknown')
            features.append(protocol_map.get(protocol, 5))
            
            # IP address analysis
            source_ip = packet_data.get('source', '0.0.0.0')
            dest_ip = packet_data.get('destination', '0.0.0.0')
            
            # Check if IPs are internal (private) or external
            source_internal = 1 if self.is_internal_ip(source_ip) else 0
            dest_internal = 1 if self.is_internal_ip(dest_ip) else 0
            features.extend([source_internal, dest_internal])
            
            # Port analysis
            port = packet_data.get('src_port', 0)
            features.extend([
                1 if port < 1024 else 0,  # Well-known ports
                1 if 1024 <= port < 49152 else 0,  # Registered ports
                1 if port >= 49152 else 0  # Dynamic/private ports
            ])
            
            # Packet size analysis
            size = packet_data.get('size', 0)
            features.extend([
                1 if size < 64 else 0,  # Small packets
                1 if 64 <= size < 512 else 0,  # Medium packets
                1 if size >= 512 else 0  # Large packets
            ])
            
            # Ensure we have exactly 10 features
            while len(features) < 10:
                features.append(0)
                
            return np.array(features[:10]).reshape(1, -1)
            
        except Exception as e:
            print(f"Error extracting features from real packet: {e}")
            return np.zeros((1, 10))
    
    def is_internal_ip(self, ip):
        """Check if IP address is internal/private"""
        try:
            if ip.startswith(('192.168.', '10.', '172.')):
                return True
            return False
        except:
            return False
    
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
            
            # Save persistent data after training
            self.save_persistent_data()
            
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

# Network Monitor (Real Packet Capture)
class RealNetworkMonitor:
    """Real network monitoring using actual packet capture"""
    
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
        
        # Initialize packet sniffer if available
        if REAL_PACKET_CAPTURE_AVAILABLE:
            try:
                self.packet_sniffer = RealPacketSniffer()
                # Always try to use real packet capture since Npcap is installed
                self.use_real_capture = True
                print("Real packet capture initialized successfully!")
                print("Npcap detected - will use real WiFi packet capture")
            except Exception as e:
                print(f"Failed to initialize real packet capture: {e}")
                self.packet_sniffer = None
                self.use_real_capture = False
        else:
            self.packet_sniffer = None
            self.use_real_capture = False
            print("Using simulated packet generation (real capture not available)")
        
    def start_monitoring(self):
        """Start network monitoring (real or simulated)"""
        self.is_monitoring = True
        self.packet_count = 0
        self.device_set.clear()
        self.device_info.clear()
        self.bandwidth_usage.clear()
        
        if self.use_real_capture and self.packet_sniffer:
            # Start real packet sniffing
            success = self.packet_sniffer.start_sniffing()
            if success:
                print("Real packet capture started successfully!")
            else:
                print("Failed to start real packet capture! Falling back to simulation.")
                self.use_real_capture = False
        else:
            print("Starting simulated packet generation...")
        
    def stop_monitoring(self):
        """Stop network monitoring"""
        self.is_monitoring = False
        if self.use_real_capture and self.packet_sniffer:
            self.packet_sniffer.stop_sniffing()
        print("Network monitoring stopped")
        
    def get_latest_packet(self):
        """Get the latest captured packet (real or simulated)"""
        if not self.is_monitoring:
            return None
            
        if self.use_real_capture and self.packet_sniffer:
            # Get recent packets from real sniffer
            recent_packets = self.packet_sniffer.get_packet_data()
            if recent_packets:
                # Return the most recent packet
                latest_packet = recent_packets[-1]
                
                # Update our local tracking
                self.packet_count = self.packet_sniffer.packet_count
                self.device_info = self.packet_sniffer.get_device_data()
                self.bandwidth_usage = self.packet_sniffer.get_bandwidth_data()
                
                # Add to device set
                if 'source' in latest_packet:
                    self.device_set.add(latest_packet['source'])
                if 'destination' in latest_packet:
                    self.device_set.add(latest_packet['destination'])
                
                # Add to ML training
                self.ml_manager.add_training_sample(latest_packet)
                
                # Train models if enough samples
                if len(self.ml_manager.training_data) >= self.ml_manager.min_samples_for_training and not self.ml_manager.is_trained:
                    self.ml_manager.train_models()
                
                print(f"Real packet captured: {latest_packet.get('source', 'Unknown')} -> {latest_packet.get('destination', 'Unknown')} ({latest_packet.get('protocol_name', 'Unknown')})")
                return latest_packet
            else:
                # No real packets available yet, wait a bit
                print("Waiting for real packets...")
                return None
        else:
            # Generate simulated packet
            return self.generate_simulated_packet()
        
        return None
    
    def generate_simulated_packet(self):
        """Generate simulated network packet (fallback)"""
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
            'protocol_name': protocol,
            'src_port': random.randint(1, 65535),
            'size': random.randint(64, 1500),
            'src_mac': mac_address,
            'device_type': device_type,
            'connection_status': 'active'
        }
        
        self.packet_count += 1
        self.device_set.add(source_ip)
        self.device_set.add(dest_ip)
        
        # Update device info
        self.update_device_info(source_ip, packet)
        self.update_device_info(dest_ip, packet)
        
        # Add to ML training
        self.ml_manager.add_training_sample(packet)
        
        # Train models if enough samples
        if len(self.ml_manager.training_data) >= self.ml_manager.min_samples_for_training and not self.ml_manager.is_trained:
            self.ml_manager.train_models()
        
        print(f"Generated simulated packet #{self.packet_count}: {source_ip} -> {dest_ip} ({protocol})")
        return packet
    
    def generate_packet(self):
        """Get latest real packet (for compatibility)"""
        return self.get_latest_packet()
    
    def get_device_type(self, ip):
        """Get device type from packet sniffer or use fallback logic"""
        if self.use_real_capture and self.packet_sniffer:
            return self.packet_sniffer.get_device_type(ip)
        else:
            # Fallback device type logic
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
        if not self.use_real_capture:
            # Handle device info for simulated packets
            if ip not in self.device_info:
                self.device_info[ip] = {
                    'first_seen': packet['timestamp'],
                    'last_seen': packet['timestamp'],
                    'packet_count': 0,
                    'total_bytes': 0,
                    'protocols': set(),
                    'ports': set(),
                    'device_type': packet.get('device_type', 'Unknown'),
                    'mac_address': packet.get('src_mac', 'Unknown'),
                    'connection_status': 'active'
                }
            
            device = self.device_info[ip]
            device['last_seen'] = packet['timestamp']
            device['packet_count'] += 1
            device['total_bytes'] += packet['size']
            device['protocols'].add(packet['protocol_name'])
            device['ports'].add(packet['src_port'])
    
    def update_bandwidth_usage(self, ip, size):
        """Update bandwidth usage"""
        # This is handled by the packet sniffer
        pass

# Flask Application
app = Flask(__name__, template_folder='../templates')
app.config['SECRET_KEY'] = 'network_security_dashboard_2024'
socketio = SocketIO(app, cors_allowed_origins="*")

# Global instances
ml_manager = WebMLManager()
network_monitor = RealNetworkMonitor(ml_manager)

# Monitoring thread
monitoring_thread = None
monitoring_active = False

def monitoring_loop():
    """Main monitoring loop for web app"""
    global monitoring_active
    while monitoring_active:
        if network_monitor.is_monitoring:
            packet = network_monitor.get_latest_packet()
            
            if packet:
                print(f"Generated packet: {packet['source']} -> {packet['destination']} ({packet['protocol_name']})")
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
                        'source': packet.get('source', 'Unknown'),
                        'destination': packet.get('destination', 'Unknown'),
                        'protocol': packet.get('protocol_name', 'Unknown'),
                        'confidence': packet['ml_prediction']['confidence']
                    }
                    network_monitor.alerts.append(alert)
                    
                    if packet['ml_prediction']['confidence'] > 0.8:
                        threat = {
                            'timestamp': packet['timestamp'],
                            'type': 'High Confidence Threat',
                            'source': packet.get('source', 'Unknown'),
                            'destination': packet.get('destination', 'Unknown'),
                            'confidence': packet['ml_prediction']['confidence'],
                            'description': f"High-risk anomaly detected by ML models"
                        }
                        network_monitor.threats.append(threat)
                
                # Check if training is complete and ask user to restart
                training_status = ml_manager.get_training_status()
                if training_status['training_progress'] >= 100 and training_status['is_trained']:
                    # Emit completion notification
                    socketio.emit('training_complete', {
                        'message': 'ML training completed! Please restart monitoring to continue with fresh data.',
                        'training_samples': training_status['training_samples'],
                        'models_available': training_status['models_available']
                    })
                
                # Emit real-time data to web clients
                socketio.emit('packet_data', {
                    'packet': {
                        'id': packet['id'],
                        'timestamp': packet['timestamp'].isoformat(),
                        'source': packet.get('source', 'Unknown'),
                        'destination': packet.get('destination', 'Unknown'),
                        'protocol': packet.get('protocol_name', 'Unknown'),
                        'port': packet.get('src_port', 0),
                        'size': packet['size'],
                        'device_type': packet.get('device_type', 'Unknown'),
                        'mac_address': packet.get('src_mac', 'Unknown')
                    },
                    'ml_prediction': packet['ml_prediction'],
                    'stats': {
                        'total_packets': network_monitor.packet_count,
                        'active_devices': len(network_monitor.device_set),
                        'alerts': len(network_monitor.alerts),
                        'threats': len(network_monitor.threats),
                        'training_status': training_status
                    }
                })
            
            time.sleep(0.1)  # Check for new packets more frequently
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

@app.route('/api/reset_training', methods=['POST'])
def reset_training():
    """Reset ML training data"""
    ml_manager.training_data.clear()
    ml_manager.is_trained = False
    ml_manager.training_progress = 0
    ml_manager.last_training_time = None
    
    # Clear persistent data file
    try:
        import os
        data_file = '../data/web_ml_data.pkl'
        if os.path.exists(data_file):
            os.remove(data_file)
            print("Persistent ML data file removed")
    except Exception as e:
        print(f"Error removing persistent data file: {e}")
    
    return jsonify({'status': 'reset', 'message': 'Training data reset successfully'})

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
    print("Note: Disable debug mode for production to prevent auto-restarts")
    socketio.run(app, debug=False, host='0.0.0.0', port=5000)
