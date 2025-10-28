#!/usr/bin/env python3
"""
Flask API Server for Network Traffic Analyzer Dashboard
"""

import os
import pandas as pd
from datetime import datetime
from flask import Flask, jsonify
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

# Data file paths
DATA_DIR = os.path.join(os.path.dirname(__file__), '..', 'data')
PACKETS_FILE = os.path.join(DATA_DIR, 'packets_extended.csv')
ALERTS_FILE = os.path.join(DATA_DIR, 'alerts.csv')

@app.route('/api/health', methods=['GET'])
def health_check():
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'message': 'Network Traffic Analyzer API is running'
    })

@app.route('/api/stats', methods=['GET'])
def get_stats():
    try:
        packets_df = pd.read_csv(PACKETS_FILE) if os.path.exists(PACKETS_FILE) else pd.DataFrame()
        alerts_df = pd.read_csv(ALERTS_FILE) if os.path.exists(ALERTS_FILE) else pd.DataFrame()
        
        stats = {
            'total_packets': len(packets_df),
            'total_alerts': len(alerts_df),
            'unique_devices': len(packets_df['src_ip'].unique()) if not packets_df.empty else 0,
            'protocols': packets_df['protocol'].value_counts().to_dict() if not packets_df.empty else {},
            'high_risk_alerts': len(alerts_df[alerts_df['risk_level'] == 'High']) if not alerts_df.empty else 0,
            'medium_risk_alerts': len(alerts_df[alerts_df['risk_level'] == 'Medium']) if not alerts_df.empty else 0,
            'low_risk_alerts': len(alerts_df[alerts_df['risk_level'] == 'Low']) if not alerts_df.empty else 0,
            'last_updated': datetime.now().isoformat()
        }
        return jsonify(stats)
    except Exception as e:
        return jsonify({'error': str(e)})

if __name__ == '__main__':
    print("🚀 Starting Network Traffic Analyzer API Server...")
    print("📊 API: http://localhost:5000")
    print("📁 Data:", DATA_DIR)
    app.run(host='0.0.0.0', port=5000, debug=True)