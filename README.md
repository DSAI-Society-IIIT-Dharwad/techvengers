# Network Security Desktop Dashboard

A professional-grade desktop application for real-time network monitoring and ML-powered threat detection.

## Features

- **Real-time Network Monitoring**: Live packet capture and analysis
- **ML-Powered Threat Detection**: 500+ sample training threshold for accurate anomaly detection
- **Enhanced Device Tracking**: MAC addresses, device types, and connection status
- **Professional Device Monitoring**: Comprehensive device dashboard with detailed information
- **Interactive Threat Injection Testing**: Test ML models with various threat types
- **Live Anomaly Detection**: Real-time training progress and model insights
- **Bandwidth Usage Tracking**: Real-time bandwidth monitoring with charts
- **Professional UI**: Modern interface with status indicators and animations

## Quick Start

1. **Install Dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

2. **Start the Dashboard**:
   ```bash
   python desktop-app/start_desktop_dashboard.py
   ```

3. **Navigate the Interface**:
   - **Dashboard**: Overview with statistics and charts
   - **Traffic Monitor**: Real-time bandwidth and protocol analysis
   - **Device Monitor**: Connected devices with detailed information
   - **Threat Analysis**: Security alerts and threat detection
   - **ML Insights**: Model training progress and performance
   - **Inject Anomaly**: Test threat injection capabilities

## ML Training

The system uses real-time ML training with a 500-sample threshold:
- **Training Progress**: Visible in header and ML Insights page
- **Models**: Isolation Forest and One-Class SVM
- **Features**: Packet size, port, protocol, IP type, and more
- **Accuracy**: Improved detection with larger training set

## Device Monitoring

Professional device tracking includes:
- **Device Types**: Router, Server, Desktop, Laptop, Mobile, IoT
- **MAC Addresses**: Unique device identification
- **Connection Status**: Active/Inactive monitoring
- **Bandwidth Usage**: Per-device traffic analysis
- **Protocol Analysis**: Port and protocol usage tracking

## Testing

Run ML tests to verify functionality:
```bash
python tests/ml-tests/test_anomaly_detection.py
python tests/ml-tests/inject_threat_test.py
python tests/ml-tests/ml_threat_summary.py
```

## Configuration

Edit `config/config.ini` to customize:
- ML training parameters
- Network monitoring settings
- UI preferences

## Requirements

- Python 3.8+
- CustomTkinter
- Matplotlib
- Scikit-learn
- NumPy
- Pandas

## Architecture

- **Desktop App**: CustomTkinter-based GUI
- **ML Engine**: Real-time training and prediction
- **Network Monitor**: Packet simulation and analysis
- **Device Tracker**: Comprehensive device management
- **Chart System**: Real-time data visualization

## Professional Features

- Modern dark theme UI
- Real-time status indicators
- Professional color scheme
- Card-based layouts
- Interactive device details
- Training progress visualization
- Bandwidth monitoring charts
- Threat injection testing

This is a production-ready network security monitoring system with enterprise-grade features and professional UI design.
