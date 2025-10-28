# Network Traffic Analyzer for Home Security

An AI-powered system that monitors live home network traffic, detects suspicious activity, and visualizes it in real-time.

## 🏗️ Project Structure

```
hackathon/
├── src/                          # Core application modules
│   ├── analyzer.py              # Main ML analysis engine
│   ├── streaming_analyzer.py    # Real-time streaming analysis
│   ├── working_packet_sniffer.py # Packet capture system
│   ├── wifi_auth_handler.py     # WiFi authentication handler
│   ├── model_manager.py         # Model management utilities
│   ├── dashboard.py             # Basic visualization dashboard
│   └── enhanced_dashboard.py    # Advanced dashboard with GeoIP
├── data/                         # Data storage
│   ├── packets.csv              # Raw packet data
│   ├── packets_extended.csv     # Extended packet dataset
│   ├── alerts.csv               # Generated security alerts
│   ├── streaming_alerts.csv      # Real-time streaming alerts
│   └── trained_models/          # Saved ML models
│       ├── isolation_forest_*.joblib
│       ├── one_class_svm_*.joblib
│       ├── local_outlier_factor_*.joblib
│       ├── standard_scaler_*.joblib
│       └── model_metadata_*.json
├── scripts/                      # Utility scripts
│   ├── launcher.py              # Main application launcher
│   ├── network_check.py         # Network diagnostics
│   ├── test_saved_models.py     # Model testing utilities
│   ├── analyze_alerts.py        # Alert analysis tools
│   ├── realtime_feeder.py       # Real-time data feeder
│   ├── dashboard_launcher.py    # Dashboard launcher
│   └── test_dashboard.py        # Dashboard testing utility
├── docs/                         # Documentation
│   ├── SETUP_GUIDE.md           # Installation and setup
│   ├── MODEL_SAVING_GUIDE.md    # Model management guide
│   ├── PART2_COMPLETE.md        # Part 2 implementation status
│   ├── PART3_COMPLETE.md        # Part 3 implementation status
│   └── FINAL_TRAINING_SUMMARY.txt # Training results
├── tests/                        # Test files (empty for now)
├── config/                       # Configuration files (empty for now)
├── requirements.txt              # Python dependencies
└── README.md                     # This file
```

## 🚀 Quick Start

### 1. Installation

```bash
# Install dependencies
pip install -r requirements.txt

# For Windows users: Install Npcap for full packet capture
# Download from: https://nmap.org/npcap/
```

### 2. Run the Application

```bash
# Use the launcher (recommended)
python scripts/launcher.py

# Or run components directly
python src/working_packet_sniffer.py    # Capture packets
python src/analyzer.py                  # Analyze captured data
python src/streaming_analyzer.py        # Real-time analysis
python scripts/dashboard_launcher.py    # Launch dashboard
```

## 📊 Features

### Part 1: Packet Capture
- **Multi-method capture**: Scapy Layer 3, raw sockets, psutil monitoring
- **WiFi authentication**: Automatic captive portal detection and handling
- **Real-time logging**: CSV output with comprehensive packet metadata
- **Cross-platform**: Works on Windows, Linux, and macOS

### Part 2: AI/ML Analysis
- **Multiple ML models**: Isolation Forest, One-Class SVM, Local Outlier Factor
- **Feature engineering**: Behavioral analysis per IP address
- **Anomaly detection**: Statistical, rule-based, and ML-based detection
- **Risk scoring**: Low, Medium, High risk levels
- **Model persistence**: Save and load trained models

### Part 3: Real-time Streaming
- **Sliding window analysis**: Continuous packet processing
- **Adaptive baselines**: Learning normal behavior patterns
- **Live alerts**: Real-time anomaly detection and alerting
- **Model updates**: Continuous learning from new data

### Part 4: Visualization Dashboard
- **Real-time dashboard**: Live network monitoring interface
- **Interactive visualizations**: Charts, graphs, and maps
- **GeoIP mapping**: World map with connection locations
- **Security alerts**: Color-coded risk levels and details
- **Auto-refresh**: Configurable real-time updates

## 🔧 Configuration

### Packet Capture Options
- **Capture count**: 10, 50, 100 packets (or unlimited)
- **Output format**: CSV with timestamp, IPs, ports, protocols, sizes
- **Authentication**: Automatic WiFi captive portal handling

### ML Model Parameters
- **Contamination**: 10% expected anomaly rate
- **Features**: 20+ behavioral metrics per IP
- **Training**: Unsupervised learning on normal traffic
- **Detection**: Multi-model ensemble approach

### Streaming Analysis
- **Window size**: 50-100 packets per analysis window
- **Update interval**: 3-5 seconds between analysis cycles
- **Baseline period**: 5-10 windows for baseline establishment

## 📈 Performance

### Training Results (11,000 packets)
- **Models trained**: Isolation Forest, One-Class SVM, Local Outlier Factor
- **Feature vectors**: 20+ behavioral metrics per IP
- **Detection accuracy**: Realistic anomaly detection with low false positives
- **Processing speed**: Real-time analysis capable

### Alert Types Detected
- **High packet rates**: Unusual traffic volume
- **Port scanning**: Multiple destination ports
- **Destination diversity**: Unusual connection patterns
- **Statistical anomalies**: Deviations from baseline behavior
- **ML anomalies**: Complex pattern-based detection

## 🛠️ Development

### Adding New Features
1. Core modules go in `src/`
2. Utility scripts go in `scripts/`
3. Data files go in `data/`
4. Documentation goes in `docs/`

### Model Management
- Models are automatically saved to `data/trained_models/`
- Use `scripts/test_saved_models.py` to test loaded models
- Model metadata includes training parameters and feature columns

### Testing
- Use `scripts/network_check.py` for network diagnostics
- Use `scripts/test_saved_models.py` for model validation
- Use `scripts/analyze_alerts.py` for alert analysis

## 📋 Requirements

### Python Dependencies
```
scapy==2.5.0
pandas==2.1.4
python-dateutil==2.8.2
psutil==5.9.6
requests==2.31.0
scikit-learn
joblib
streamlit
plotly
geoip2
pycountry
```

### System Requirements
- **Python**: 3.8+
- **OS**: Windows 10+, Linux, macOS
- **Privileges**: Administrator/root for full packet capture
- **Network**: Active internet connection for WiFi authentication

## 🔒 Security Features

### Detected Threats
- **Port scanning**: Rapid connection attempts to multiple ports
- **DDoS patterns**: High packet rates from single sources
- **Beaconing**: Low-rate, long-duration connections
- **Protocol anomalies**: Unusual protocol usage patterns
- **Geographic anomalies**: Connections to suspicious IP ranges

### Alert Levels
- **HIGH**: Immediate attention required (port scans, DDoS)
- **MEDIUM**: Suspicious activity (high packet rates, unusual patterns)
- **LOW**: Potential anomalies (statistical deviations)

## 📚 Documentation

- **Setup Guide**: `docs/SETUP_GUIDE.md`
- **Model Guide**: `docs/MODEL_SAVING_GUIDE.md`
- **Implementation Status**: `docs/PART2_COMPLETE.md`
- **Training Summary**: `docs/FINAL_TRAINING_SUMMARY.txt`

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## 📄 License

This project is part of a hackathon submission for network security analysis.

## 🆘 Support

For issues and questions:
1. Check the documentation in `docs/`
2. Run `scripts/network_check.py` for diagnostics
3. Check the launcher options in `scripts/launcher.py`

---

**Status**: ✅ Complete - All four parts implemented and tested
**Last Updated**: October 2025
**Models Trained**: 11,000+ packets with realistic results
**Dashboard**: Real-time visualization with GeoIP mapping
