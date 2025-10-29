# Model Saving and Loading Functionality

This document describes the model saving and loading functionality added to the network traffic analysis system.

## Overview

Both `analyzer.py` and `streaming_analyzer.py` now automatically save trained ML models to disk after training. This allows you to:

- Persist trained models for future use
- Load pre-trained models without retraining
- Share models between different analysis sessions
- Maintain model versioning with timestamps

## Model Storage

### Directory Structure
```
trained_models/
├── isolation_forest_20241201_143022.joblib
├── one_class_svm_20241201_143022.joblib
├── local_outlier_factor_20241201_143022.joblib
├── standard_scaler_20241201_143022.joblib
├── model_metadata_20241201_143022.json
├── streaming_isolation_forest_20241201_143022.joblib
├── streaming_one_class_svm_20241201_143022.joblib
├── streaming_local_outlier_factor_20241201_143022.joblib
├── streaming_standard_scaler_20241201_143022.joblib
└── streaming_model_metadata_20241201_143022.json
```

### File Naming Convention
- **Batch models**: `{model_name}_{timestamp}.joblib`
- **Streaming models**: `streaming_{model_name}_{timestamp}.joblib`
- **Scalers**: `{type}_scaler_{timestamp}.joblib`
- **Metadata**: `{type}_model_metadata_{timestamp}.json`

## Usage

### Automatic Saving
Models are automatically saved when training completes:

```python
# In analyzer.py
analyzer = NetworkTrafficAnalyzer('packets_extended.csv')
analyzer.load_data()
analyzer.clean_data()
analyzer.feature_engineering()
analyzer.train_anomaly_models()  # Models saved automatically here

# In streaming_analyzer.py
processor = StreamingPacketProcessor()
processor.start_processing()
# Models saved automatically when baseline is established
```

### Manual Loading
You can load previously trained models:

```python
# Load batch models
analyzer = NetworkTrafficAnalyzer('packets_extended.csv')
if analyzer.load_models():  # Loads most recent models
    print("Models loaded successfully!")
    # Now you can use analyzer.detect_anomalies() without retraining

# Load specific timestamp
analyzer.load_models("20241201_143022")

# Load streaming models
processor = StreamingPacketProcessor()
if processor.load_models():  # Loads most recent streaming models
    print("Streaming models loaded successfully!")
```

### Model Manager Utility
Use the `model_manager.py` script to manage your models:

```python
from model_manager import ModelManager

manager = ModelManager()

# List all available models
manager.print_model_info()

# Test model predictions
manager.test_model_prediction("batch")
manager.test_model_prediction("streaming")

# Clean up old models (older than 7 days)
manager.cleanup_old_models(keep_days=7)
```

## Model Metadata

Each model set includes metadata with:
- Training timestamp
- Model types trained
- Feature columns used
- Training data information
- Model-specific parameters

Example metadata:
```json
{
  "timestamp": "20241201_143022",
  "models_trained": ["isolation_forest", "one_class_svm", "local_outlier_factor"],
  "scalers_trained": ["standard"],
  "feature_columns": [
    "packet_count", "avg_packet_size", "max_packet_size", 
    "unique_destinations", "packets_per_second", ...
  ],
  "training_data_shape": [150, 17],
  "model_type": "batch"
}
```

## Benefits

1. **Performance**: Avoid retraining models every time
2. **Consistency**: Use the same models across different analysis sessions
3. **Versioning**: Keep track of different model versions
4. **Sharing**: Share trained models with team members
5. **Backup**: Models are preserved even if training data changes

## Requirements

The model saving functionality requires:
- `joblib` library (for efficient model serialization)
- `json` library (for metadata storage)
- `os` library (for file operations)

These are included in the updated imports in both analyzer files.

## Troubleshooting

### Common Issues

1. **Permission Errors**: Ensure write permissions to the project directory
2. **Disk Space**: Models can be large; ensure sufficient disk space
3. **Import Errors**: Make sure `joblib` is installed: `pip install joblib`

### Model Loading Issues

1. **Missing Files**: Check if all model files exist for the timestamp
2. **Version Mismatch**: Ensure scikit-learn versions are compatible
3. **Feature Mismatch**: Verify feature columns match between training and loading

## Example Workflow

```python
# 1. Train and save models
analyzer = NetworkTrafficAnalyzer('packets_extended.csv')
analyzer.load_data()
analyzer.clean_data()
analyzer.feature_engineering()
analyzer.train_anomaly_models()  # Saves models automatically

# 2. Later, load and use models
analyzer2 = NetworkTrafficAnalyzer('new_packets.csv')
analyzer2.load_data()
analyzer2.clean_data()
analyzer2.feature_engineering()

# Load previously trained models
if analyzer2.load_models():
    alerts = analyzer2.detect_anomalies()  # Use loaded models
else:
    print("No models found, training new ones...")
    analyzer2.train_anomaly_models()
```

This functionality ensures your trained models are preserved and can be reused efficiently across different analysis sessions.
