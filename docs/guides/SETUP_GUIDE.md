# Desktop Application Setup Guide

## Installation

1. **Install Python Dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

2. **Verify Installation**:
   ```bash
   python desktop-app/start_desktop_dashboard.py
   ```

## Usage

### Starting the Application
```bash
python desktop-app/start_desktop_dashboard.py
```

### Navigation
- **Dashboard**: Main overview with statistics
- **Traffic Monitor**: Bandwidth and protocol analysis
- **Device Monitor**: Connected devices management
- **Threat Analysis**: Security alerts and detection
- **ML Insights**: Model training and performance
- **Inject Anomaly**: Threat testing capabilities

### ML Training Process
1. Start monitoring to begin data collection
2. Wait for 500 samples to complete training
3. Monitor progress in header and ML Insights
4. Models automatically train when threshold reached

### Device Monitoring
- View all connected devices in table format
- Click devices for detailed information
- Monitor bandwidth usage per device
- Track device types and connection status

## Configuration

Edit `config/config.ini` for customization:
- ML training parameters
- Network monitoring settings
- UI preferences

## Troubleshooting

### Common Issues
1. **Chart not appearing**: Ensure matplotlib is installed
2. **ML training not starting**: Check if monitoring is active
3. **Device list empty**: Wait for packet generation
4. **Performance issues**: Close other applications

### Dependencies
- CustomTkinter: Modern UI framework
- Matplotlib: Chart visualization
- Scikit-learn: ML algorithms
- NumPy/Pandas: Data processing

## Features

- Real-time network monitoring
- ML-powered threat detection
- Professional device tracking
- Interactive threat testing
- Bandwidth monitoring
- Modern UI design