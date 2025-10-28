# Network Traffic Analysis & ML Security System

A comprehensive network security analysis system with machine learning capabilities for real-time threat detection and packet analysis.

## 🚀 Project Overview

This project provides a complete network security solution with:
- **Real-time packet capture and analysis**
- **Machine learning-based anomaly detection**
- **Automated threat detection**
- **Historical data analysis**

## 📁 Project Structure

```
hackathon/
├── 📁 src/                          # Core application source code
│   ├── analyzer.py                  # Batch ML analysis engine
│   ├── streaming_analyzer.py       # Real-time streaming analysis
│   ├── model_manager.py            # ML model management
│   ├── wifi_auth_handler.py       # WiFi authentication handler
│   └── working_packet_sniffer.py  # Packet capture engine
│
├── 📁 data/                         # Data storage and models
│   ├── 📁 trained_models/          # Saved ML models
│   │   ├── isolation_forest_*.joblib
│   │   ├── one_class_svm_*.joblib
│   │   ├── local_outlier_factor_*.joblib
│   │   ├── standard_scaler_*.joblib
│   │   └── *_metadata_*.json
│   ├── alerts.csv                  # Generated security alerts
│   ├── streaming_alerts.csv       # Real-time alerts
│   ├── packets.csv                # Raw packet data
│   ├── packets_extended.csv      # Enhanced packet data
│   └── packets_clean.csv         # Cleaned packet data
│
├── 📁 scripts/                      # Utility and helper scripts
│   ├── analyze_alerts.py          # Alert analysis tools
│   ├── comparison_analysis.py    # Comparative analysis
│   ├── launcher.py               # Main system launcher
│   ├── ml_model_summary.py      # ML model summary
│   ├── model_summary.py         # Model statistics
│   ├── network_check.py         # Network connectivity check
│   ├── realtime_feeder.py      # Real-time data feeder
│   ├── simple_packet_sniffer.py # Basic packet sniffer
│   └── test_*.py               # Various test scripts
│
├── 📁 web-app/                      # Web application
│   ├── 📁 network-dashboard/      # React dashboard
│   │   └── 📁 src/
│   │       ├── App.js
│   │       ├── App.css
│   │       └── 📁 components/
│   │           ├── Alerts.js
│   │           ├── Dashboard.js
│   │           └── NetworkMap.js
│   ├── api_server.py             # Web API server
│   ├── demo.html                 # Demo page
│   ├── start_web_app.py         # Web app launcher
│   └── test_api.py              # API testing
│
├── 📁 docs/                        # Documentation
│   ├── 📁 archive/               # Archived files
│   │   ├── live_dashboard.html
│   │   ├── live_network_dashboard.html
│   │   ├── ml_security_dashboard.html
│   │   └── network_dashboard.html
│   ├── FINAL_TRAINING_SUMMARY.txt
│   ├── MODEL_SAVING_GUIDE.md
│   ├── PART2_COMPLETE.md
│   ├── PART3_COMPLETE.md
│   └── SETUP_GUIDE.md
│
├── 📁 tests/                       # Test files
│   ├── test_complete_system.py
│   ├── test_live_system.py
│   └── test_web_app.py
│
├── 📁 config/                      # Configuration files
│   └── config.ini
│
├── 📄 complete_dashboard.html      # Main dashboard interface
├── 📄 README.md                   # This file
├── 📄 requirements.txt            # Python dependencies
├── 📄 FINAL_PROJECT_SUMMARY.md    # Project summary
├── 🚀 start_*.bat                 # System launchers
└── 🧹 cleanup.py                  # Project cleanup utility
```

## 🛠️ Key Components

### 1. **Core Analysis Engines**
- **`src/analyzer.py`**: Batch ML analysis for historical data
- **`src/streaming_analyzer.py`**: Real-time streaming analysis
- **`src/live_network_analyzer.py`**: Live network monitoring

### 2. **Machine Learning Models**
- **Isolation Forest**: Ensemble-based anomaly detection
- **One-Class SVM**: Novelty detection with kernel methods
- **Local Outlier Factor**: Density-based anomaly detection
- **Standard Scaler**: Feature normalization

### 3. **Web Interface**
- **`complete_dashboard.html`**: Main dashboard interface
- **`web-app/`**: React-based web application
- **API servers**: RESTful API endpoints

### 4. **Data Management**
- **`data/trained_models/`**: Saved ML models with timestamps
- **`data/*.csv`**: Packet data and alerts
- **`src/model_manager.py`**: Model loading/saving utilities

## 🚀 Quick Start

### Prerequisites
```bash
pip install -r requirements.txt
```

### Launch Options

1. **Complete System**:
   ```bash
   start_complete_system.bat
   ```

2. **Live Monitoring**:
   ```bash
   start_live_system.bat
   ```

3. **ML Analysis**:
   ```bash
   start_ml_system.bat
   ```

4. **Web Application**:
   ```bash
   start_web_app.bat
   ```

## 📊 Features

### 🔍 **Network Analysis**
- Real-time packet capture
- Protocol analysis (TCP, UDP, ICMP)
- Traffic pattern recognition
- Bandwidth monitoring

### 🤖 **Machine Learning**
- Automated anomaly detection
- Threat classification
- Pattern learning
- Model persistence

### 📈 **Dashboards**
- Interactive network maps
- Real-time alerts
- Historical analysis
- Performance metrics

### 🚨 **Security Features**
- DDoS detection
- Port scanning detection
- Unusual traffic pattern identification
- Automated alerting

## 📋 Usage Examples

### Load Pre-trained Models
```python
from src.analyzer import NetworkTrafficAnalyzer

analyzer = NetworkTrafficAnalyzer('data/packets_extended.csv')
analyzer.load_models()  # Loads saved ML models
alerts = analyzer.detect_anomalies()
```

### Real-time Monitoring
```python
from src.streaming_analyzer import StreamingPacketProcessor

processor = StreamingPacketProcessor()
processor.load_models()  # Loads streaming models
processor.start_processing()
```

### Model Management
```python
from src.model_manager import ModelManager

manager = ModelManager()
manager.print_model_info()
manager.test_model_prediction()
```

## 🔧 Configuration

Edit `config/config.ini` to customize:
- Network interfaces
- Analysis parameters
- Alert thresholds
- Model settings

## 📚 Documentation

- **`docs/SETUP_GUIDE.md`**: Detailed setup instructions
- **`docs/MODEL_SAVING_GUIDE.md`**: ML model management
- **`docs/PART2_COMPLETE.md`**: Analysis engine documentation
- **`docs/PART3_COMPLETE.md`**: Web interface documentation

## 🧪 Testing

Run tests to verify system functionality:
```bash
python tests/test_complete_system.py
python tests/test_live_system.py
python tests/test_web_app.py
```

## 🧹 Maintenance

Use the cleanup utility to maintain project organization:
```bash
python cleanup.py
```

## 📈 Performance

- **Training Time**: < 1 minute per model
- **Storage**: ~227 KB for all models
- **Real-time Processing**: 50 packets per window
- **Update Interval**: 3 seconds

## 🤝 Contributing

1. Follow the organized project structure
2. Add new features to appropriate directories
3. Update documentation for new components
4. Test thoroughly before committing

## 📄 License

This project is part of a hackathon submission for network security analysis.

---

**Status**: ✅ Production Ready  
**Last Updated**: October 29, 2025  
**Version**: 1.0.0