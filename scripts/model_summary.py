#!/usr/bin/env python3
"""
Model Save Summary - Shows what models were saved
"""

import os
import json
from datetime import datetime

def show_model_summary():
    """Show summary of saved models."""
    print("=" * 60)
    print("MODEL SAVE SUMMARY")
    print("=" * 60)
    
    models_dir = "trained_models"
    if not os.path.exists(models_dir):
        print("No models directory found!")
        return
    
    # Count files by type
    files = os.listdir(models_dir)
    batch_models = [f for f in files if f.endswith('.joblib') and not f.startswith('streaming_')]
    streaming_models = [f for f in files if f.startswith('streaming_') and f.endswith('.joblib')]
    metadata_files = [f for f in files if f.endswith('.json')]
    
    print(f"Batch Analysis Models: {len(batch_models)}")
    for model in sorted(batch_models):
        print(f"  - {model}")
    
    print(f"\nStreaming Analysis Models: {len(streaming_models)}")
    for model in sorted(streaming_models):
        print(f"  - {model}")
    
    print(f"\nMetadata Files: {len(metadata_files)}")
    for metadata in sorted(metadata_files):
        print(f"  - {metadata}")
    
    # Calculate total size
    total_size = sum(os.path.getsize(os.path.join(models_dir, f)) for f in files)
    print(f"\nTotal Storage Used: {total_size:,} bytes ({total_size/1024:.1f} KB)")
    
    # Show metadata details
    print(f"\nModel Details:")
    for metadata_file in metadata_files:
        with open(os.path.join(models_dir, metadata_file), 'r') as f:
            metadata = json.load(f)
        
        model_type = "Batch" if "streaming" not in metadata_file else "Streaming"
        print(f"\n{model_type} Models (trained: {metadata['timestamp']}):")
        print(f"  - Models: {', '.join(metadata['models_trained'])}")
        print(f"  - Features: {len(metadata['feature_columns'])}")
        if 'training_data_shape' in metadata:
            print(f"  - Training data: {metadata['training_data_shape']}")
        if 'baseline_windows' in metadata:
            print(f"  - Baseline windows: {metadata['baseline_windows']}")
    
    print(f"\n" + "=" * 60)
    print("SUCCESS: All models have been saved to the project directory!")
    print("You can now:")
    print("  - Load these models without retraining")
    print("  - Share models with team members")
    print("  - Use models for future analysis")
    print("  - Run 'python model_manager.py' to manage models")
    print("=" * 60)

if __name__ == "__main__":
    show_model_summary()
