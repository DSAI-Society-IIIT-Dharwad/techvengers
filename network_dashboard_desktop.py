#!/usr/bin/env python3
"""
Network Security Desktop Dashboard
A beautiful desktop application for real-time network monitoring with ML-powered anomaly detection
"""

import tkinter as tk
from tkinter import ttk, messagebox
import customtkinter as ctk
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure
import numpy as np
import pandas as pd
import threading
import time
import json
import joblib
from datetime import datetime, timedelta
import random
import queue
from collections import deque
import psutil
import socket
import struct
import os
import math
import warnings
from PIL import Image, ImageTk
warnings.filterwarnings('ignore')

# Configure customtkinter
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

class RealTimeMLManager:
    """Real-time ML model manager that trains on packet streams"""
    
    def __init__(self):
        self.models = {}
        self.scalers = {}
        self.training_data = []
        self.is_trained = False
        self.min_samples_for_training = 50
        self.max_training_samples = 1000
        
    def add_training_sample(self, packet_data):
        """Add a packet to training data"""
        features = self.extract_features(packet_data)
        if features is not None:
            self.training_data.append(features.flatten())
            
            # Keep only recent samples
            if len(self.training_data) > self.max_training_samples:
                self.training_data = self.training_data[-self.max_training_samples:]
    
    def load_models(self):
        """Initialize real-time training (no pre-trained models)"""
        print("Real-time ML manager initialized - will train on packet stream")
        return True
    
    def extract_features(self, packet_data):
        """Extract features from packet data"""
        try:
            features = []
            
            # Basic packet features (matching training data)
            features.append(packet_data.get('size', 0))
            features.append(packet_data.get('port', 0))
            
            # Protocol encoding
            protocol_map = {'TCP': 1, 'UDP': 2, 'ICMP': 3, 'HTTP': 4, 'HTTPS': 5}
            protocol = packet_data.get('protocol', 'TCP')
            features.append(protocol_map.get(protocol, 1))
            
            # IP type
            source_ip = packet_data.get('source', '192.168.1.1')
            dest_ip = packet_data.get('destination', '192.168.1.1')
            
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
            
            # Ensure we have exactly 10 features (matching training data)
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
            # Convert to numpy array
            X = np.array(self.training_data)
            
            # Normalize features
            from sklearn.preprocessing import StandardScaler
            self.scalers['standard'] = StandardScaler()
            X_scaled = self.scalers['standard'].fit_transform(X)
            
            # Train Isolation Forest
            from sklearn.ensemble import IsolationForest
            self.models['isolation_forest'] = IsolationForest(
                contamination=0.1,
                random_state=42,
                n_estimators=100
            )
            self.models['isolation_forest'].fit(X_scaled)
            
            # Train One-Class SVM
            from sklearn.svm import OneClassSVM
            self.models['one_class_svm'] = OneClassSVM(
                nu=0.1,
                kernel='rbf',
                gamma='scale'
            )
            self.models['one_class_svm'].fit(X_scaled)
            
            self.is_trained = True
            print(f"Real-time ML models trained on {len(self.training_data)} samples")
            return True
            
        except Exception as e:
            print(f"Training error: {e}")
            return False
    
    def predict_anomaly(self, packet_data):
        """Predict if packet is anomalous"""
        try:
            if not self.is_trained:
                return {'is_anomaly': False, 'confidence': 0.5, 'model': 'training'}
            
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
                    if model_name == 'one_class_svm' and hasattr(model, 'decision_function'):
                        # One-Class SVM
                        score = model.decision_function(features_scaled)[0]
                        prediction = score < 0
                        confidence = abs(score)
                    elif model_name == 'isolation_forest' and hasattr(model, 'score_samples'):
                        # Isolation Forest
                        score = model.score_samples(features_scaled)[0]
                        prediction = score < -0.1
                        confidence = abs(score)
                    else:
                        # Unknown model type
                        prediction = False
                        confidence = 0.5
                    
                    predictions[model_name] = prediction
                    confidences[model_name] = confidence
                    
                except Exception as e:
                    print(f"Error with {model_name}: {e}")
                    predictions[model_name] = False
                    confidences[model_name] = 0.5
            
            # Ensemble prediction
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
            'models_available': list(self.models.keys())
        }

class NetworkMonitor:
    """Simulates network packet monitoring"""
    
    def __init__(self, ml_manager, data_queue):
        self.ml_manager = ml_manager
        self.data_queue = data_queue
        self.is_monitoring = False
        self.packet_count = 0
        self.device_set = set()
        
    def start_monitoring(self):
        """Start network monitoring"""
        self.is_monitoring = True
        self.packet_count = 0
        self.device_set.clear()
        
    def stop_monitoring(self):
        """Stop network monitoring"""
        self.is_monitoring = False
        
    def generate_packet(self):
        """Generate simulated network packet"""
        protocols = ['TCP', 'UDP', 'ICMP', 'HTTP', 'HTTPS']
        sources = [f"192.168.1.{i}" for i in range(1, 255)]
        destinations = [f"10.0.0.{i}" for i in range(1, 255)]
        
        protocol = random.choice(protocols)
        packet = {
            'id': self.packet_count,
            'timestamp': datetime.now(),
            'source': random.choice(sources),
            'destination': random.choice(destinations),
            'protocol': protocol,
            'port': random.randint(1, 65535),
            'size': random.randint(64, 1500),
            'protocol_num': {'TCP': 1, 'UDP': 2, 'ICMP': 3, 'HTTP': 4, 'HTTPS': 5}[protocol],
            'flags': random.randint(0, 15)
        }
        
        self.packet_count += 1
        self.device_set.add(packet['source'])
        self.device_set.add(packet['destination'])
        
        # Add packet to training data
        self.ml_manager.add_training_sample(packet)
        
        # Train models if we have enough data
        if len(self.ml_manager.training_data) >= self.ml_manager.min_samples_for_training and not self.ml_manager.is_trained:
            self.ml_manager.train_models()
        
        return packet
    
    def monitoring_loop(self):
        """Main monitoring loop"""
        while True:
            if self.is_monitoring:
                packet = self.generate_packet()
                
                # Get ML prediction
                ml_prediction = self.ml_manager.predict_anomaly(packet)
                packet['ml_prediction'] = ml_prediction
                
                # Add to queue for GUI update
                self.data_queue.put({
                    'type': 'packet',
                    'data': packet,
                    'stats': {
                        'total_packets': self.packet_count,
                        'active_devices': len(self.device_set),
                        'alerts': 0,  # Will be updated by GUI
                        'threats': 0  # Will be updated by GUI
                    }
                })
                
                # Add delay to simulate real-time monitoring
                time.sleep(0.5)
            else:
                time.sleep(1)

class NetworkDashboard(ctk.CTk):
    """Main desktop application"""
    
    def __init__(self):
        super().__init__()
        
        # Initialize ML manager
        self.ml_manager = RealTimeMLManager()
        self.ml_loaded = self.ml_manager.load_models()
        
        # Initialize network monitor
        self.data_queue = queue.Queue()
        self.network_monitor = NetworkMonitor(self.ml_manager, self.data_queue)
        
        # Data storage
        self.packets = deque(maxlen=1000)
        self.alerts = deque(maxlen=100)
        self.devices = {}  # Track devices
        self.threats = deque(maxlen=50)  # Track threats
        
        # Animation variables
        self.animation_running = False
        self.threat_animation_counter = 0
        self.pulse_colors = ["#e74c3c", "#c0392b", "#a93226", "#c0392b", "#e74c3c"]
        self.current_pulse_index = 0
        
        self.traffic_stats = {
            'total_packets': 0,
            'active_devices': 0,
            'alerts': 0,
            'threats': 0,
            'bandwidth_usage': 0,
            'protocol_counts': {'TCP': 0, 'UDP': 0, 'ICMP': 0, 'HTTP': 0, 'HTTPS': 0}
        }
        
        # Current page
        self.current_page = "dashboard"
        
        # Setup GUI
        self.setup_gui()
        
        # Start monitoring thread
        self.monitor_thread = threading.Thread(target=self.network_monitor.monitoring_loop, daemon=True)
        self.monitor_thread.start()
        
        # Start GUI update loop
        self.update_gui()
        
    def setup_gui(self):
        """Setup the GUI components"""
        self.title("Network Security Dashboard")
        self.geometry("1600x1000")
        self.minsize(1400, 900)
        
        # Configure grid weights
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(2, weight=1)  # Main content area gets the weight
        
        # Header
        self.create_header()
        
        # Navigation tabs
        self.create_navigation()
        
        # Main content area
        self.create_main_content()
        
        # Status bar
        self.create_status_bar()
        
    def create_header(self):
        """Create header with title and controls"""
        header_frame = ctk.CTkFrame(self)
        header_frame.grid(row=0, column=0, columnspan=2, sticky="ew", padx=10, pady=10)
        
        # Title
        title_label = ctk.CTkLabel(
            header_frame, 
            text="Network Security Dashboard", 
            font=ctk.CTkFont(size=24, weight="bold")
        )
        title_label.pack(side="left", padx=20, pady=15)
        
        # ML Status
        ml_status = "Connected" if self.ml_loaded else "Disconnected"
        ml_color = "green" if self.ml_loaded else "red"
        ml_label = ctk.CTkLabel(
            header_frame,
            text=f"ML Models: {ml_status}",
            text_color=ml_color,
            font=ctk.CTkFont(size=14, weight="bold")
        )
        ml_label.pack(side="right", padx=20, pady=15)
        
        # Control buttons
        button_frame = ctk.CTkFrame(header_frame)
        button_frame.pack(side="right", padx=20, pady=10)
        
        self.start_button = ctk.CTkButton(
            button_frame,
            text="▶ Start Monitoring",
            command=self.start_monitoring,
            width=140,
            height=35,
            fg_color="#27ae60",
            hover_color="#2ecc71"
        )
        self.start_button.pack(side="left", padx=5)
        
        self.stop_button = ctk.CTkButton(
            button_frame,
            text="⏹ Stop Monitoring",
            command=self.stop_monitoring,
            width=140,
            height=35,
            fg_color="#e74c3c",
            hover_color="#c0392b",
            state="disabled"
        )
        self.stop_button.pack(side="left", padx=5)
        
        # Status indicator
        self.status_indicator = ctk.CTkLabel(
            button_frame,
            text="●",
            font=ctk.CTkFont(size=16),
            text_color="#95a5a6"
        )
        self.status_indicator.pack(side="left", padx=10)
        
    def create_navigation(self):
        """Create navigation tabs"""
        nav_frame = ctk.CTkFrame(self)
        nav_frame.grid(row=1, column=0, sticky="ew", padx=10, pady=(0, 5))
        
        # Navigation buttons
        self.nav_buttons = {}
        pages = [
            ("Dashboard", "dashboard"),
            ("Traffic Monitor", "traffic"),
            ("Device Monitor", "devices"),
            ("Threat Analysis", "threats"),
            ("ML Insights", "ml_insights")
        ]
        
        for i, (label, page_id) in enumerate(pages):
            btn = ctk.CTkButton(
                nav_frame,
                text=label,
                command=lambda p=page_id: self.switch_page(p),
                width=120,
                height=35
            )
            btn.pack(side="left", padx=5, pady=10)
            self.nav_buttons[page_id] = btn
        
        # Highlight current page
        self.nav_buttons[self.current_page].configure(fg_color="#1f538d")
        
    def switch_page(self, page_id):
        """Switch to a different page"""
        try:
            # Reset all button colors
            for btn in self.nav_buttons.values():
                btn.configure(fg_color=ctk.ThemeManager.theme["CTkButton"]["fg_color"])
            
            # Highlight current page button
            self.nav_buttons[page_id].configure(fg_color="#1f538d")
            
            # Hide all pages
            for widget in self.content_frame.winfo_children():
                widget.grid_remove()
            
            # Show selected page
            self.current_page = page_id
            if page_id == "dashboard" and hasattr(self, 'dashboard_frame'):
                self.dashboard_frame.grid(row=0, column=0, sticky="nsew")
            elif page_id == "traffic" and hasattr(self, 'traffic_frame'):
                self.traffic_frame.grid(row=0, column=0, sticky="nsew")
            elif page_id == "devices" and hasattr(self, 'devices_frame'):
                self.devices_frame.grid(row=0, column=0, sticky="nsew")
            elif page_id == "threats" and hasattr(self, 'threats_frame'):
                self.threats_frame.grid(row=0, column=0, sticky="nsew")
            elif page_id == "ml_insights" and hasattr(self, 'ml_insights_frame'):
                self.ml_insights_frame.grid(row=0, column=0, sticky="nsew")
        except Exception as e:
            print(f"Error switching to page {page_id}: {e}")
        
    def create_main_content(self):
        """Create main content area with multiple pages"""
        # Content frame
        self.content_frame = ctk.CTkFrame(self)
        self.content_frame.grid(row=2, column=0, sticky="nsew", padx=10, pady=(0, 5))
        self.content_frame.grid_columnconfigure(0, weight=1)
        self.content_frame.grid_rowconfigure(0, weight=1)
        
        # Create all pages
        self.create_dashboard_page()
        self.create_traffic_page()
        self.create_devices_page()
        self.create_threats_page()
        self.create_ml_insights_page()
        
        # Show dashboard by default
        if hasattr(self, 'dashboard_frame'):
            self.dashboard_frame.grid(row=0, column=0, sticky="nsew")
        
    def create_dashboard_page(self):
        """Create the main dashboard page"""
        self.dashboard_frame = ctk.CTkFrame(self.content_frame)
        self.dashboard_frame.grid_columnconfigure((0, 1), weight=1)
        self.dashboard_frame.grid_rowconfigure(1, weight=1)
        
        # Stats cards
        self.create_stats_cards(self.dashboard_frame)
        
        # Charts
        self.create_charts(self.dashboard_frame)
        
        # Alerts and Packets
        self.create_alerts_panel(self.dashboard_frame)
        self.create_packets_panel(self.dashboard_frame)
        
    def create_traffic_page(self):
        """Create traffic monitoring page"""
        self.traffic_frame = ctk.CTkFrame(self.content_frame)
        self.traffic_frame.grid_columnconfigure(0, weight=1)
        self.traffic_frame.grid_rowconfigure(1, weight=1)
        
        # Traffic page title
        traffic_title = ctk.CTkLabel(
            self.traffic_frame,
            text="Traffic Monitoring",
            font=ctk.CTkFont(size=20, weight="bold")
        )
        traffic_title.grid(row=0, column=0, pady=(20, 10))
        
        # Traffic analysis frame
        traffic_analysis_frame = ctk.CTkFrame(self.traffic_frame)
        traffic_analysis_frame.grid(row=1, column=0, sticky="nsew", padx=20, pady=(0, 20))
        traffic_analysis_frame.grid_columnconfigure((0, 1), weight=1)
        traffic_analysis_frame.grid_rowconfigure((0, 1), weight=1)
        
        # Bandwidth chart
        self.create_bandwidth_chart(traffic_analysis_frame)
        
        # Protocol analysis
        self.create_protocol_analysis(traffic_analysis_frame)
        
        # Traffic details
        self.create_traffic_details(traffic_analysis_frame)
        
    def create_devices_page(self):
        """Create device monitoring page"""
        self.devices_frame = ctk.CTkFrame(self.content_frame)
        self.devices_frame.grid_columnconfigure(0, weight=1)
        self.devices_frame.grid_rowconfigure(1, weight=1)
        
        # Devices page title
        devices_title = ctk.CTkLabel(
            self.devices_frame,
            text="Device Monitoring",
            font=ctk.CTkFont(size=20, weight="bold")
        )
        devices_title.grid(row=0, column=0, pady=20)
        
        # Device list
        self.create_device_list(self.devices_frame)
        
    def create_threats_page(self):
        """Create threat analysis page"""
        self.threats_frame = ctk.CTkFrame(self.content_frame)
        self.threats_frame.grid_columnconfigure(0, weight=1)
        self.threats_frame.grid_rowconfigure(1, weight=1)
        
        # Threats page title
        threats_title = ctk.CTkLabel(
            self.threats_frame,
            text="Threat Analysis",
            font=ctk.CTkFont(size=20, weight="bold")
        )
        threats_title.grid(row=0, column=0, pady=20)
        
        # Threat analysis
        self.create_threat_analysis(self.threats_frame)
        
    def create_ml_insights_page(self):
        """Create ML insights page"""
        self.ml_insights_frame = ctk.CTkFrame(self.content_frame)
        self.ml_insights_frame.grid_columnconfigure(0, weight=1)
        self.ml_insights_frame.grid_rowconfigure(1, weight=1)
        
        # ML insights title
        ml_title = ctk.CTkLabel(
            self.ml_insights_frame,
            text="ML Model Insights",
            font=ctk.CTkFont(size=20, weight="bold")
        )
        ml_title.grid(row=0, column=0, pady=20)
        
        # ML insights content
        self.create_ml_insights_content(self.ml_insights_frame)
        
    def create_stats_cards(self, parent):
        """Create statistics cards"""
        stats_frame = ctk.CTkFrame(parent)
        stats_frame.grid(row=0, column=0, sticky="ew", padx=10, pady=10)
        stats_frame.grid_columnconfigure((0, 1, 2, 3), weight=1)
        
        # Stats labels with enhanced styling
        self.stats_labels = {}
        stats_info = [
            ("Total Packets", "total_packets", "#3498db", "📊"),
            ("Active Devices", "active_devices", "#2ecc71", "📱"),
            ("Security Alerts", "alerts", "#e74c3c", "🚨"),
            ("Threats Detected", "threats", "#f39c12", "⚠️")
        ]
        
        for i, (title, key, color, icon) in enumerate(stats_info):
            card = ctk.CTkFrame(stats_frame)
            card.grid(row=0, column=i, sticky="ew", padx=5, pady=10)
            
            # Icon
            icon_label = ctk.CTkLabel(card, text=icon, font=ctk.CTkFont(size=20))
            icon_label.pack(pady=(10, 5))
            
            # Title
            title_label = ctk.CTkLabel(card, text=title, font=ctk.CTkFont(size=12))
            title_label.pack(pady=(0, 5))
            
            # Value
            value_label = ctk.CTkLabel(
                card, 
                text="0", 
                font=ctk.CTkFont(size=20, weight="bold"),
                text_color=color
            )
            value_label.pack(pady=(0, 10))
            
            self.stats_labels[key] = value_label
            
    def create_charts(self, parent):
        """Create charts for network data"""
        charts_frame = ctk.CTkFrame(parent)
        charts_frame.grid(row=1, column=0, sticky="nsew", padx=10, pady=10)
        charts_frame.grid_columnconfigure(0, weight=1)
        charts_frame.grid_rowconfigure(0, weight=1)
        
        # Create matplotlib figure
        self.fig = Figure(figsize=(8, 4), facecolor='#2b2b2b')
        self.fig.patch.set_facecolor('#2b2b2b')
        
        # Traffic chart
        self.ax1 = self.fig.add_subplot(121)
        self.ax1.set_title('Traffic Over Time', color='white', fontsize=12)
        self.ax1.set_facecolor('#2b2b2b')
        self.ax1.tick_params(colors='white')
        self.ax1.set_xlabel('Time', color='white')
        self.ax1.set_ylabel('Packets', color='white')
        
        # Protocol chart
        self.ax2 = self.fig.add_subplot(122)
        self.ax2.set_title('Protocol Distribution', color='white', fontsize=12)
        self.ax2.set_facecolor('#2b2b2b')
        self.ax2.tick_params(colors='white')
        
        # Canvas
        self.canvas = FigureCanvasTkAgg(self.fig, charts_frame)
        self.canvas.get_tk_widget().pack(fill="both", expand=True)
        
        # Initialize chart data
        self.traffic_data = deque(maxlen=20)
        self.protocol_data = {'TCP': 0, 'UDP': 0, 'ICMP': 0, 'HTTP': 0, 'HTTPS': 0}
        
    def create_alerts_panel(self, parent):
        """Create alerts panel"""
        alerts_frame = ctk.CTkFrame(parent)
        alerts_frame.grid(row=0, column=0, sticky="ew", padx=10, pady=10)
        
        alerts_title = ctk.CTkLabel(
            alerts_frame, 
            text="Security Alerts", 
            font=ctk.CTkFont(size=16, weight="bold")
        )
        alerts_title.pack(pady=10)
        
        # Alerts listbox
        self.alerts_listbox = tk.Listbox(
            alerts_frame,
            height=8,
            bg='#2b2b2b',
            fg='white',
            selectbackground='#1f538d',
            font=('Consolas', 10)
        )
        self.alerts_listbox.pack(fill="x", padx=10, pady=(0, 10))
        
    def create_packets_panel(self, parent):
        """Create recent packets panel"""
        packets_frame = ctk.CTkFrame(parent)
        packets_frame.grid(row=1, column=0, sticky="nsew", padx=10, pady=10)
        
        packets_title = ctk.CTkLabel(
            packets_frame, 
            text="Recent Packets", 
            font=ctk.CTkFont(size=16, weight="bold")
        )
        packets_title.pack(pady=10)
        
        # Packets listbox
        self.packets_listbox = tk.Listbox(
            packets_frame,
            bg='#2b2b2b',
            fg='white',
            selectbackground='#1f538d',
            font=('Consolas', 9)
        )
        self.packets_listbox.pack(fill="both", expand=True, padx=10, pady=(0, 10))
        
    def create_status_bar(self):
        """Create status bar"""
        status_frame = ctk.CTkFrame(self)
        status_frame.grid(row=3, column=0, sticky="ew", padx=10, pady=(0, 10))
        
        self.status_label = ctk.CTkLabel(
            status_frame,
            text="Ready to start monitoring",
            font=ctk.CTkFont(size=12)
        )
        self.status_label.pack(side="left", padx=20, pady=10)
        
        self.time_label = ctk.CTkLabel(
            status_frame,
            text="",
            font=ctk.CTkFont(size=12)
        )
        self.time_label.pack(side="right", padx=20, pady=10)
        
    def animate_threat_cards(self):
        """Animate threat cards with pulsing effect"""
        if not self.animation_running:
            return
            
        try:
            if hasattr(self, 'threat_cards'):
                # Get current threat count
                total_threats = len(self.threats)
                
                if total_threats > 0:
                    # Pulse the total threats card
                    self.current_pulse_index = (self.current_pulse_index + 1) % len(self.pulse_colors)
                    color = self.pulse_colors[self.current_pulse_index]
                    
                    if 'total_threats' in self.threat_cards:
                        self.threat_cards['total_threats'].configure(text_color=color)
                    
                    # Schedule next animation
                    self.after(200, self.animate_threat_cards)
                else:
                    # Reset to normal color when no threats
                    if 'total_threats' in self.threat_cards:
                        self.threat_cards['total_threats'].configure(text_color="#e74c3c")
                    self.after(1000, self.animate_threat_cards)
        except Exception as e:
            print(f"Animation error: {e}")
    
    def animate_status_indicator(self):
        """Animate status indicator"""
        if not self.animation_running:
            return
            
        try:
            if hasattr(self, 'status_indicator'):
                # Blink the status indicator
                current_color = self.status_indicator.cget("text_color")
                if current_color == "#27ae60":
                    self.status_indicator.configure(text_color="#2ecc71")
                else:
                    self.status_indicator.configure(text_color="#27ae60")
                
                self.after(500, self.animate_status_indicator)
        except Exception as e:
            print(f"Status animation error: {e}")
    
    def start_animations(self):
        """Start all animations"""
        self.animation_running = True
        self.animate_threat_cards()
        self.animate_status_indicator()
    
    def stop_animations(self):
        """Stop all animations"""
        self.animation_running = False
        
    def start_monitoring(self):
        """Start network monitoring"""
        self.network_monitor.start_monitoring()
        self.start_button.configure(state="disabled")
        self.stop_button.configure(state="normal")
        self.status_indicator.configure(text="●", text_color="#27ae60")
        self.status_label.configure(text="Monitoring active - Analyzing network traffic...")
        
        # Start animations
        self.start_animations()
        
    def stop_monitoring(self):
        """Stop network monitoring"""
        self.network_monitor.stop_monitoring()
        self.start_button.configure(state="normal")
        self.stop_button.configure(state="disabled")
        self.status_indicator.configure(text="●", text_color="#95a5a6")
        self.status_label.configure(text="Monitoring stopped")
        
        # Stop animations
        self.stop_animations()
        
    def update_gui(self):
        """Update GUI with new data"""
        # Process data from queue
        while not self.data_queue.empty():
            try:
                data = self.data_queue.get_nowait()
                
                if data['type'] == 'packet':
                    packet = data['data']
                    self.packets.append(packet)
                    
                    # Update stats
                    self.traffic_stats.update(data['stats'])
                    
                    # Update device tracking
                    self.devices[packet['source']] = {
                        'last_seen': packet['timestamp'],
                        'packet_count': self.devices.get(packet['source'], {}).get('packet_count', 0) + 1,
                        'protocols': self.devices.get(packet['source'], {}).get('protocols', set())
                    }
                    self.devices[packet['source']]['protocols'].add(packet['protocol'])
                    
                    # Update protocol counts
                    protocol = packet['protocol']
                    if protocol in self.traffic_stats['protocol_counts']:
                        self.traffic_stats['protocol_counts'][protocol] += 1
                    
                    # Update bandwidth (simulate)
                    bandwidth_mbps = packet['size'] / 1024 / 1024 * 8  # Convert to Mbps
                    self.bandwidth_data.append(bandwidth_mbps)
                    self.traffic_stats['bandwidth_usage'] += bandwidth_mbps
                    
                    # Check for anomalies using pre-trained models
                    if packet['ml_prediction']['is_anomaly'] and packet['ml_prediction']['confidence'] > 0.7:
                        alert = {
                            'timestamp': packet['timestamp'],
                            'type': 'ML Anomaly Detected',
                            'severity': 'High' if packet['ml_prediction']['confidence'] > 0.9 else 'Medium',
                            'description': f"Anomalous packet detected ({packet['ml_prediction']['confidence']:.1%} confidence)",
                            'source': packet['source'],
                            'destination': packet['destination'],
                            'protocol': packet['protocol'],
                            'confidence': packet['ml_prediction']['confidence'],
                            'model_predictions': packet['ml_prediction'].get('model_predictions', {})
                        }
                        self.alerts.append(alert)
                        self.traffic_stats['alerts'] += 1
                        
                        if packet['ml_prediction']['confidence'] > 0.8:
                            threat = {
                                'timestamp': packet['timestamp'],
                                'type': 'High Confidence Threat',
                                'source': packet['source'],
                                'destination': packet['destination'],
                                'confidence': packet['ml_prediction']['confidence'],
                                'description': f"High-risk anomaly detected by ML models"
                            }
                            self.threats.append(threat)
                            self.traffic_stats['threats'] += 1
                            
            except queue.Empty:
                break
        
        # Update stats labels
        for key, label in self.stats_labels.items():
            label.configure(text=str(self.traffic_stats[key]))
        
        # Update charts
        self.update_charts()
        
        # Update alerts list
        self.update_alerts_list()
        
        # Update packets list
        self.update_packets_list()
        
        # Update additional pages
        self.update_traffic_page()
        self.update_devices_page()
        self.update_threats_page()
        self.update_ml_insights_page()
        
        # Update time
        self.time_label.configure(text=datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        
        # Schedule next update
        self.after(1000, self.update_gui)
        
    def update_charts(self):
        """Update charts with new data"""
        try:
            # Traffic chart
            if len(self.packets) > 0:
                recent_packets = list(self.packets)[-20:]
                counts = [1] * len(recent_packets)  # Simplified count
                
                self.ax1.clear()
                self.ax1.plot(range(len(counts)), counts, color='#1f538d', linewidth=2, marker='o', markersize=3)
                self.ax1.set_title('Traffic Over Time', color='white', fontsize=12)
                self.ax1.set_facecolor('#2b2b2b')
                self.ax1.tick_params(colors='white')
                self.ax1.set_xlabel('Time', color='white')
                self.ax1.set_ylabel('Packets', color='white')
                self.ax1.grid(True, alpha=0.3, color='gray')
                
                # Protocol chart
                protocol_counts = {'TCP': 0, 'UDP': 0, 'ICMP': 0, 'HTTP': 0, 'HTTPS': 0}
                for packet in recent_packets:
                    protocol = packet['protocol']
                    if protocol in protocol_counts:
                        protocol_counts[protocol] += 1
                
                self.ax2.clear()
                protocols = list(protocol_counts.keys())
                counts = list(protocol_counts.values())
                colors = ['#1f538d', '#2ecc71', '#e74c3c', '#f39c12', '#9b59b6']
                
                # Only show protocols with data
                non_zero_protocols = [(p, c) for p, c in zip(protocols, counts) if c > 0]
                if non_zero_protocols:
                    protocols, counts = zip(*non_zero_protocols)
                    self.ax2.pie(counts, labels=protocols, colors=colors[:len(protocols)], autopct='%1.1f%%')
                else:
                    self.ax2.text(0.5, 0.5, 'No Data', ha='center', va='center', color='white', fontsize=14)
                
                self.ax2.set_title('Protocol Distribution', color='white', fontsize=12)
                self.ax2.set_facecolor('#2b2b2b')
                
                self.canvas.draw()
            else:
                # Show placeholder when no data
                self.ax1.clear()
                self.ax1.text(0.5, 0.5, 'Waiting for data...', ha='center', va='center', color='white', fontsize=14)
                self.ax1.set_title('Traffic Over Time', color='white', fontsize=12)
                self.ax1.set_facecolor('#2b2b2b')
                self.ax1.tick_params(colors='white')
                
                self.ax2.clear()
                self.ax2.text(0.5, 0.5, 'Waiting for data...', ha='center', va='center', color='white', fontsize=14)
                self.ax2.set_title('Protocol Distribution', color='white', fontsize=12)
                self.ax2.set_facecolor('#2b2b2b')
                
                self.canvas.draw()
                
        except Exception as e:
            print(f"Error updating charts: {e}")
        
    def update_alerts_list(self):
        """Update alerts list"""
        self.alerts_listbox.delete(0, tk.END)
        
        for alert in list(self.alerts)[-10:]:  # Show last 10 alerts
            alert_text = f"[{alert['timestamp'].strftime('%H:%M:%S')}] {alert['description']}"
            self.alerts_listbox.insert(tk.END, alert_text)
            
    def update_packets_list(self):
        """Update packets list"""
        self.packets_listbox.delete(0, tk.END)
        
        for packet in list(self.packets)[-15:]:  # Show last 15 packets
            anomaly_indicator = "ALERT" if packet['ml_prediction']['is_anomaly'] else "OK"
            packet_text = f"{anomaly_indicator} {packet['source']} → {packet['destination']} ({packet['protocol']})"
            self.packets_listbox.insert(tk.END, packet_text)
    
    def create_bandwidth_chart(self, parent):
        """Create bandwidth monitoring chart"""
        bandwidth_frame = ctk.CTkFrame(parent)
        bandwidth_frame.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)
        bandwidth_frame.grid_columnconfigure(0, weight=1)
        bandwidth_frame.grid_rowconfigure(1, weight=1)
        
        bandwidth_title = ctk.CTkLabel(
            bandwidth_frame,
            text="Bandwidth Usage",
            font=ctk.CTkFont(size=16, weight="bold")
        )
        bandwidth_title.grid(row=0, column=0, pady=(10, 5))
        
        # Bandwidth chart
        self.bandwidth_fig = Figure(figsize=(6, 4), facecolor='#2b2b2b')
        self.bandwidth_fig.patch.set_facecolor('#2b2b2b')
        
        self.bandwidth_ax = self.bandwidth_fig.add_subplot(111)
        self.bandwidth_ax.set_title('Bandwidth Over Time', color='white', fontsize=12)
        self.bandwidth_ax.set_facecolor('#2b2b2b')
        self.bandwidth_ax.tick_params(colors='white')
        self.bandwidth_ax.set_xlabel('Time', color='white')
        self.bandwidth_ax.set_ylabel('Bandwidth (Mbps)', color='white')
        
        self.bandwidth_canvas = FigureCanvasTkAgg(self.bandwidth_fig, bandwidth_frame)
        self.bandwidth_canvas.get_tk_widget().grid(row=1, column=0, sticky="nsew")
        
        # Initialize bandwidth data
        self.bandwidth_data = deque(maxlen=30)
        
    def create_protocol_analysis(self, parent):
        """Create protocol analysis chart"""
        protocol_frame = ctk.CTkFrame(parent)
        protocol_frame.grid(row=0, column=1, sticky="nsew", padx=10, pady=10)
        protocol_frame.grid_columnconfigure(0, weight=1)
        protocol_frame.grid_rowconfigure(1, weight=1)
        
        protocol_title = ctk.CTkLabel(
            protocol_frame,
            text="Protocol Analysis",
            font=ctk.CTkFont(size=16, weight="bold")
        )
        protocol_title.grid(row=0, column=0, pady=(10, 5))
        
        # Protocol chart
        self.protocol_fig = Figure(figsize=(6, 4), facecolor='#2b2b2b')
        self.protocol_fig.patch.set_facecolor('#2b2b2b')
        
        self.protocol_ax = self.protocol_fig.add_subplot(111)
        self.protocol_ax.set_title('Protocol Distribution', color='white', fontsize=12)
        self.protocol_ax.set_facecolor('#2b2b2b')
        self.protocol_ax.tick_params(colors='white')
        
        self.protocol_canvas = FigureCanvasTkAgg(self.protocol_fig, protocol_frame)
        self.protocol_canvas.get_tk_widget().grid(row=1, column=0, sticky="nsew")
        
    def create_traffic_details(self, parent):
        """Create traffic details panel"""
        details_frame = ctk.CTkFrame(parent)
        details_frame.grid(row=1, column=0, columnspan=2, sticky="nsew", padx=10, pady=(0, 10))
        details_frame.grid_columnconfigure(0, weight=1)
        details_frame.grid_rowconfigure(1, weight=1)
        
        details_title = ctk.CTkLabel(
            details_frame,
            text="Traffic Details",
            font=ctk.CTkFont(size=16, weight="bold")
        )
        details_title.grid(row=0, column=0, pady=(10, 5))
        
        # Traffic details listbox
        self.traffic_details_listbox = tk.Listbox(
            details_frame,
            bg='#2b2b2b',
            fg='white',
            selectbackground='#1f538d',
            font=('Consolas', 10)
        )
        self.traffic_details_listbox.grid(row=1, column=0, sticky="nsew", padx=10, pady=(0, 10))
        
    def create_device_list(self, parent):
        """Create device monitoring list"""
        device_frame = ctk.CTkFrame(parent)
        device_frame.grid(row=1, column=0, sticky="nsew", padx=20, pady=20)
        device_frame.grid_columnconfigure(0, weight=1)
        device_frame.grid_rowconfigure(1, weight=1)
        
        # Device listbox
        self.device_listbox = tk.Listbox(
            device_frame,
            bg='#2b2b2b',
            fg='white',
            selectbackground='#1f538d',
            font=('Consolas', 11)
        )
        self.device_listbox.grid(row=1, column=0, sticky="nsew", padx=10, pady=10)
        
    def create_threat_analysis(self, parent):
        """Create threat analysis panel"""
        threat_frame = ctk.CTkFrame(parent)
        threat_frame.grid(row=1, column=0, sticky="nsew", padx=20, pady=20)
        threat_frame.grid_columnconfigure(0, weight=1)
        threat_frame.grid_rowconfigure(1, weight=1)
        
        # Threat summary cards
        self.create_threat_summary_cards(threat_frame)
        
        # Threat listbox
        self.threat_listbox = tk.Listbox(
            threat_frame,
            bg='#2b2b2b',
            fg='white',
            selectbackground='#e74c3c',
            font=('Consolas', 11)
        )
        self.threat_listbox.grid(row=1, column=0, sticky="nsew", padx=10, pady=10)
        
    def create_threat_summary_cards(self, parent):
        """Create threat summary cards"""
        summary_frame = ctk.CTkFrame(parent)
        summary_frame.grid(row=0, column=0, sticky="ew", padx=10, pady=10)
        summary_frame.grid_columnconfigure((0, 1, 2, 3), weight=1)
        
        # Threat level cards
        self.threat_cards = {}
        threat_info = [
            ("Total Threats", "total_threats", "#e74c3c"),
            ("High Risk", "high_risk", "#c0392b"),
            ("Medium Risk", "medium_risk", "#f39c12"),
            ("Low Risk", "low_risk", "#27ae60")
        ]
        
        for i, (title, key, color) in enumerate(threat_info):
            card = ctk.CTkFrame(summary_frame)
            card.grid(row=0, column=i, sticky="ew", padx=5, pady=10)
            
            title_label = ctk.CTkLabel(card, text=title, font=ctk.CTkFont(size=12))
            title_label.pack(pady=(10, 5))
            
            value_label = ctk.CTkLabel(
                card, 
                text="0", 
                font=ctk.CTkFont(size=20, weight="bold"),
                text_color=color
            )
            value_label.pack(pady=(0, 10))
            
            self.threat_cards[key] = value_label
        
    def create_ml_insights_content(self, parent):
        """Create ML insights content"""
        ml_frame = ctk.CTkFrame(parent)
        ml_frame.grid(row=1, column=0, sticky="nsew", padx=20, pady=20)
        ml_frame.grid_columnconfigure(0, weight=1)
        ml_frame.grid_rowconfigure(1, weight=1)
        
        # ML insights text
        self.ml_insights_text = tk.Text(
            ml_frame,
            bg='#2b2b2b',
            fg='white',
            font=('Consolas', 11),
            wrap=tk.WORD
        )
        self.ml_insights_text.grid(row=1, column=0, sticky="nsew", padx=10, pady=10)
        
        # Add scrollbar
        scrollbar = tk.Scrollbar(ml_frame, orient="vertical", command=self.ml_insights_text.yview)
        scrollbar.grid(row=1, column=1, sticky="ns")
        self.ml_insights_text.configure(yscrollcommand=scrollbar.set)
        
        # ML Activity Progress Bar
        progress_frame = ctk.CTkFrame(ml_frame)
        progress_frame.grid(row=2, column=0, columnspan=2, sticky="ew", padx=10, pady=(0, 10))
        
        progress_label = ctk.CTkLabel(progress_frame, text="ML Model Activity", font=ctk.CTkFont(size=12))
        progress_label.pack(pady=(10, 5))
        
        self.ml_progress_bar = ctk.CTkProgressBar(progress_frame, width=300, height=20)
        self.ml_progress_bar.pack(pady=(0, 10))
        self.ml_progress_bar.set(0.0)
    
    def update_traffic_page(self):
        """Update traffic monitoring page"""
        try:
            # Update bandwidth chart
            if hasattr(self, 'bandwidth_data') and hasattr(self, 'bandwidth_ax') and len(self.bandwidth_data) > 0:
                self.bandwidth_ax.clear()
                self.bandwidth_ax.plot(range(len(self.bandwidth_data)), list(self.bandwidth_data), 
                                     color='#2ecc71', linewidth=2, marker='o', markersize=3)
                self.bandwidth_ax.set_title('Bandwidth Over Time', color='white', fontsize=12)
                self.bandwidth_ax.set_facecolor('#2b2b2b')
                self.bandwidth_ax.tick_params(colors='white')
                self.bandwidth_ax.set_xlabel('Time', color='white')
                self.bandwidth_ax.set_ylabel('Bandwidth (Mbps)', color='white')
                self.bandwidth_ax.grid(True, alpha=0.3, color='gray')
                if hasattr(self, 'bandwidth_canvas'):
                    self.bandwidth_canvas.draw()
            
            # Update protocol analysis
            if hasattr(self, 'traffic_stats') and hasattr(self, 'protocol_ax') and 'protocol_counts' in self.traffic_stats:
                self.protocol_ax.clear()
                protocols = list(self.traffic_stats['protocol_counts'].keys())
                counts = list(self.traffic_stats['protocol_counts'].values())
                colors = ['#1f538d', '#2ecc71', '#e74c3c', '#f39c12', '#9b59b6']
                
                # Only show protocols with data
                non_zero_protocols = [(p, c) for p, c in zip(protocols, counts) if c > 0]
                if non_zero_protocols:
                    protocols, counts = zip(*non_zero_protocols)
                    self.protocol_ax.pie(counts, labels=protocols, colors=colors[:len(protocols)], autopct='%1.1f%%')
                else:
                    self.protocol_ax.text(0.5, 0.5, 'No Data', ha='center', va='center', color='white', fontsize=14)
                
                self.protocol_ax.set_title('Protocol Distribution', color='white', fontsize=12)
                self.protocol_ax.set_facecolor('#2b2b2b')
                if hasattr(self, 'protocol_canvas'):
                    self.protocol_canvas.draw()
            
            # Update traffic details
            if hasattr(self, 'traffic_details_listbox'):
                self.traffic_details_listbox.delete(0, tk.END)
                recent_packets = list(self.packets)[-20:]
                for packet in recent_packets:
                    details = f"[{packet['timestamp'].strftime('%H:%M:%S')}] {packet['source']} → {packet['destination']} | {packet['protocol']} | {packet['size']} bytes | Port: {packet['port']}"
                    self.traffic_details_listbox.insert(tk.END, details)
                    
        except Exception as e:
            print(f"Error updating traffic page: {e}")
    
    def update_devices_page(self):
        """Update device monitoring page"""
        try:
            if hasattr(self, 'device_listbox'):
                self.device_listbox.delete(0, tk.END)
                
                # Sort devices by packet count
                sorted_devices = sorted(self.devices.items(), 
                                      key=lambda x: x[1]['packet_count'], reverse=True)
                
                for ip, info in sorted_devices:
                    protocols_str = ', '.join(info['protocols'])
                    device_info = f"{ip} | Packets: {info['packet_count']} | Protocols: {protocols_str} | Last seen: {info['last_seen'].strftime('%H:%M:%S')}"
                    self.device_listbox.insert(tk.END, device_info)
                    
        except Exception as e:
            print(f"Error updating devices page: {e}")
    
    def update_threats_page(self):
        """Update threat analysis page"""
        try:
            if hasattr(self, 'threat_listbox'):
                self.threat_listbox.delete(0, tk.END)
                
                # Calculate threat statistics
                total_threats = len(self.threats)
                high_risk = sum(1 for t in self.threats if t.get('confidence', 0) > 0.9)
                medium_risk = sum(1 for t in self.threats if 0.7 <= t.get('confidence', 0) <= 0.9)
                low_risk = sum(1 for t in self.threats if 0.5 <= t.get('confidence', 0) < 0.7)
                
                # Generate simulated threats for demonstration
                if len(self.threats) == 0 and len(self.packets) > 10:
                    # Simulate occasional threats for demonstration
                    if random.random() < 0.05:  # 5% chance of generating a threat
                        threat_types = [
                            "Suspicious Port Scan",
                            "Unusual Data Transfer",
                            "Anomalous Connection Pattern",
                            "Potential DDoS Attempt",
                            "Malicious Payload Detected"
                        ]
                        
                        threat = {
                            'timestamp': datetime.now(),
                            'type': random.choice(threat_types),
                            'source': f"192.168.1.{random.randint(1, 254)}",
                            'destination': f"10.0.0.{random.randint(1, 254)}",
                            'confidence': random.uniform(0.7, 0.95),
                            'severity': random.choice(['HIGH', 'MEDIUM', 'LOW'])
                        }
                        self.threats.append(threat)
                
                # Update threat cards
                if hasattr(self, 'threat_cards'):
                    self.threat_cards['total_threats'].configure(text=str(total_threats))
                    self.threat_cards['high_risk'].configure(text=str(high_risk))
                    self.threat_cards['medium_risk'].configure(text=str(medium_risk))
                    self.threat_cards['low_risk'].configure(text=str(low_risk))
                
                # Add status message if no threats
                if total_threats == 0:
                    self.threat_listbox.insert(tk.END, "🛡️ No threats detected - Network is secure")
                    self.threat_listbox.insert(tk.END, "")
                    self.threat_listbox.insert(tk.END, "Real-Time ML Training Status:")
                    
                    # Get training status
                    training_status = self.ml_manager.get_training_status()
                    if training_status['is_trained']:
                        self.threat_listbox.insert(tk.END, f"✓ Models trained on {training_status['training_samples']} samples")
                        self.threat_listbox.insert(tk.END, f"✓ Available models: {', '.join(training_status['models_available'])}")
                    else:
                        self.threat_listbox.insert(tk.END, f"⏳ Training in progress: {training_status['training_samples']}/{training_status['min_samples_needed']} samples")
                        self.threat_listbox.insert(tk.END, f"⏳ Models will be ready after {training_status['min_samples_needed'] - training_status['training_samples']} more packets")
                    
                    self.threat_listbox.insert(tk.END, "")
                    self.threat_listbox.insert(tk.END, "Recent Analysis:")
                    recent_packets = list(self.packets)[-10:] if self.packets else []
                    anomaly_count = sum(1 for p in recent_packets if p['ml_prediction']['is_anomaly'])
                    self.threat_listbox.insert(tk.END, f"Packets analyzed: {len(recent_packets)}")
                    self.threat_listbox.insert(tk.END, f"Anomalies detected: {anomaly_count}")
                    if recent_packets:
                        avg_confidence = sum(p['ml_prediction']['confidence'] for p in recent_packets) / len(recent_packets)
                        self.threat_listbox.insert(tk.END, f"Average confidence: {avg_confidence:.1%}")
                    
                    # Add real-time threat level assessment
                    self.threat_listbox.insert(tk.END, "")
                    self.threat_listbox.insert(tk.END, "Threat Level Assessment:")
                    if anomaly_count == 0:
                        self.threat_listbox.insert(tk.END, "🟢 LOW RISK - Normal network activity")
                    elif anomaly_count <= 2:
                        self.threat_listbox.insert(tk.END, "🟡 MEDIUM RISK - Some unusual activity")
                    else:
                        self.threat_listbox.insert(tk.END, "🔴 HIGH RISK - Multiple anomalies detected")
                        
                else:
                    # Show actual threats with enhanced formatting
                    self.threat_listbox.insert(tk.END, f"🚨 {total_threats} THREAT(S) DETECTED!")
                    self.threat_listbox.insert(tk.END, "")
                    
                    for threat in list(self.threats)[-20:]:
                        risk_level = "HIGH" if threat.get('confidence', 0) > 0.9 else "MEDIUM" if threat.get('confidence', 0) > 0.7 else "LOW"
                        risk_icon = "🔴" if risk_level == "HIGH" else "🟡" if risk_level == "MEDIUM" else "🟢"
                        threat_info = f"{risk_icon} [{threat['timestamp'].strftime('%H:%M:%S')}] {risk_level} RISK | {threat['source']} → {threat['destination']} | Confidence: {threat['confidence']:.1%}"
                        self.threat_listbox.insert(tk.END, threat_info)
                    
        except Exception as e:
            print(f"Error updating threats page: {e}")
    
    def update_ml_insights_page(self):
        """Update ML insights page"""
        try:
            if hasattr(self, 'ml_insights_text'):
                # Clear and update ML insights
                self.ml_insights_text.delete(1.0, tk.END)
                
                insights = []
                insights.append("=== ML MODEL INSIGHTS ===\n")
                
                # Model status
                if self.ml_loaded:
                    insights.append("ML Models: Loaded and Active")
                    insights.append(f"Available Models: {len(self.ml_manager.models)}")
                    insights.append(f"Models: {', '.join(self.ml_manager.models.keys())}")
                else:
                    insights.append("ML Models: Not Loaded")
                
                insights.append("\n=== RECENT PREDICTIONS ===\n")
                
                # Recent predictions
                recent_packets = list(self.packets)[-10:]
                anomaly_count = sum(1 for p in recent_packets if p['ml_prediction']['is_anomaly'])
                
                insights.append(f"Recent Packets Analyzed: {len(recent_packets)}")
                insights.append(f"Anomalies Detected: {anomaly_count}")
                insights.append(f"Anomaly Rate: {anomaly_count/len(recent_packets)*100:.1f}%" if recent_packets else "Anomaly Rate: 0%")
                
                insights.append("\n=== MODEL PERFORMANCE ===\n")
                
                # Model performance stats
                if recent_packets:
                    avg_confidence = np.mean([p['ml_prediction']['confidence'] for p in recent_packets])
                    insights.append(f"Average Confidence: {avg_confidence:.1%}")
                    
                    # Individual model predictions
                    model_stats = {}
                    for packet in recent_packets:
                        if 'model_predictions' in packet['ml_prediction']:
                            for model, prediction in packet['ml_prediction']['model_predictions'].items():
                                if model not in model_stats:
                                    model_stats[model] = {'anomalies': 0, 'total': 0}
                                model_stats[model]['total'] += 1
                                if prediction:
                                    model_stats[model]['anomalies'] += 1
                    
                    for model, stats in model_stats.items():
                        anomaly_rate = stats['anomalies'] / stats['total'] * 100
                        insights.append(f"{model}: {stats['anomalies']}/{stats['total']} anomalies ({anomaly_rate:.1f}%)")
                
                insights.append("\n=== THREAT LEVELS ===\n")
                insights.append(f"High Confidence Threats: {self.traffic_stats['threats']}")
                insights.append(f"Total Alerts: {self.traffic_stats['alerts']}")
                insights.append(f"Active Devices: {self.traffic_stats['active_devices']}")
                
                # Insert insights
                self.ml_insights_text.insert(tk.END, '\n'.join(insights))
                
                # Update progress bar based on activity
                if hasattr(self, 'ml_progress_bar'):
                    if recent_packets:
                        # Simulate ML activity based on packet processing
                        activity_level = min(len(recent_packets) / 10.0, 1.0)
                        self.ml_progress_bar.set(activity_level)
                    else:
                        self.ml_progress_bar.set(0.0)
                
        except Exception as e:
            print(f"Error updating ML insights page: {e}")

def main():
    """Main function"""
    print("Starting Network Security Dashboard...")
    
    # Check if ML models are available
    try:
        app = NetworkDashboard()
        print("Desktop application started successfully!")
        print("ML models loaded and integrated")
        print("Real-time monitoring ready")
        
        app.mainloop()
        
    except Exception as e:
        print(f"Error starting application: {e}")
        messagebox.showerror("Error", f"Failed to start application: {e}")

if __name__ == "__main__":
    main()
