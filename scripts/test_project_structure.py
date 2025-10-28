#!/usr/bin/env python3
"""
Test script to verify the organized project structure
"""

import os
import sys

def test_project_structure():
    """Test that all expected directories and files exist."""
    print("Testing Project Structure")
    print("=" * 40)
    
    # Expected directories
    directories = [
        'src',
        'data',
        'data/trained_models',
        'docs',
        'scripts',
        'tests',
        'config'
    ]
    
    # Expected core files
    core_files = [
        'src/analyzer.py',
        'src/streaming_analyzer.py',
        'src/working_packet_sniffer.py',
        'src/wifi_auth_handler.py',
        'src/model_manager.py',
        'scripts/launcher.py',
        'scripts/network_check.py',
        'scripts/test_saved_models.py',
        'docs/SETUP_GUIDE.md',
        'docs/MODEL_SAVING_GUIDE.md',
        'requirements.txt',
        'README.md',
        '.gitignore',
        'config/config.ini'
    ]
    
    # Test directories
    print("Testing directories...")
    for directory in directories:
        if os.path.exists(directory):
            print(f"  [OK] {directory}")
        else:
            print(f"  [MISSING] {directory}")
    
    print("\nTesting core files...")
    for file_path in core_files:
        if os.path.exists(file_path):
            print(f"  [OK] {file_path}")
        else:
            print(f"  [MISSING] {file_path}")
    
    # Test data files
    print("\nTesting data files...")
    data_files = [
        'data/packets.csv',
        'data/packets_extended.csv',
        'data/alerts.csv',
        'data/streaming_alerts.csv'
    ]
    
    for file_path in data_files:
        if os.path.exists(file_path):
            size = os.path.getsize(file_path)
            print(f"  [OK] {file_path} ({size} bytes)")
        else:
            print(f"  [MISSING] {file_path}")
    
    # Test model files
    print("\nTesting model files...")
    models_dir = 'data/trained_models'
    if os.path.exists(models_dir):
        model_files = [f for f in os.listdir(models_dir) if f.endswith('.joblib')]
        metadata_files = [f for f in os.listdir(models_dir) if f.endswith('.json')]
        
        print(f"  [OK] Found {len(model_files)} model files")
        print(f"  [OK] Found {len(metadata_files)} metadata files")
        
        for model_file in model_files:
            print(f"    - {model_file}")
    else:
        print("  [MISSING] No trained models directory found")
    
    print("\n" + "=" * 40)
    print("Project structure test complete!")

if __name__ == "__main__":
    test_project_structure()
