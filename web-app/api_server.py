#!/usr/bin/env python3
"""
Flask API Server for Network Traffic Analyzer Dashboard
Serves data from CSV files to React frontend
"""

import os
import sys
import pandas as pd
import json
from datetime import datetime, timedelta
from flask import Flask, jsonify, request
from flask_cors import CORS
import numpy as np

app = Flask(__name__)
CORS(app)  # Enable CORS for React frontend

# Data file paths
DATA_DIR = os.path.join(os.path.dirname(__file__), '..', 'data')
PACKETS_FILE = os.path.join(DATA_DIR, 'packets_extended.csv')
ALERTS_FILE = os.path.join(DATA_DIR, 'alerts.csv')
STREAMING_ALERTS_FILE = os.path.join(DATA_DIR, 'streaming_alerts.csv')

def load_data():
    """Load and cache data from CSV files"""
    try:
        # Load packets data
        if os.path.exists(PACKETS_FILE):
            packets_df = pd.read_csv(PACKETS_FILE)
            packets_df['timestamp'] = pd.to_datetime(packets_df['timestamp'])
        else:
            packets_df = pd.DataFrame()
        
        # Load alerts data
        alerts_df = pd.DataFrame()
        if os.path.exists(ALERTS_FILE):
            alerts_df = pd.read_csv(ALERTS_FILE)
            alerts_df['timestamp'] = pd.to_datetime(alerts_df['timestamp'])
        
        # Load streaming alerts if available
        if os.path.exists(STREAMING_ALERTS_FILE):
            streaming_alerts_df = pd.read_csv(STREAMING_ALERTS_FILE)
            streaming_alerts_df['timestamp'] = pd.to_datetime(streaming_alerts_df['timestamp'])
            alerts_df = pd.concat([alerts_df, streaming_alerts_df], ignore_index=True)
        
        return packets_df, alerts_df
    except Exception as e:
        print(f"Error loading data: {e}")
        return pd.DataFrame(), pd.DataFrame()

@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'message': 'Network Traffic Analyzer API is running'
    })

@app.route('/api/stats', methods=['GET'])
def get_stats():
    """Get overall statistics"""
    packets_df, alerts_df = load_data()
    
    stats = {
        'total_packets': len(packets_df),
        'total_alerts': len(alerts_df),
        'unique_devices': len(packets_df['src_ip'].unique()) if not packets_df.empty else 0,
        'unique_destinations': len(packets_df['dst_ip'].unique()) if not packets_df.empty else 0,
        'protocols': packets_df['protocol'].value_counts().to_dict() if not packets_df.empty else {},
        'high_risk_alerts': len(alerts_df[alerts_df['risk_level'] == 'High']) if not alerts_df.empty else 0,
        'medium_risk_alerts': len(alerts_df[alerts_df['risk_level'] == 'Medium']) if not alerts_df.empty else 0,
        'low_risk_alerts': len(alerts_df[alerts_df['risk_level'] == 'Low']) if not alerts_df.empty else 0,
        'last_updated': datetime.now().isoformat()
    }
    
    return jsonify(stats)

if __name__ == '__main__':
    print("🚀 Starting Network Traffic Analyzer API Server...")
    print("📊 API will be available at: http://localhost:5000")
    print("🔗 React app should connect to: http://localhost:3000")
    print("📁 Data directory:", DATA_DIR)
    print("📄 Data files:")
    print(f"   Packets: {PACKETS_FILE} ({'✅' if os.path.exists(PACKETS_FILE) else '❌'})")
    print(f"   Alerts: {ALERTS_FILE} ({'✅' if os.path.exists(ALERTS_FILE) else '❌'})")
    print(f"   Streaming: {STREAMING_ALERTS_FILE} ({'✅' if os.path.exists(STREAMING_ALERTS_FILE) else '❌'})")
    
    app.run(host='0.0.0.0', port=5000, debug=True)