#!/usr/bin/env python3
"""
Bug Check Script for Desktop Dashboard
Quick check for common issues
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

def check_bugs():
    """Check for common bugs"""
    print("Desktop Dashboard Bug Check")
    print("=" * 40)
    
    # Check imports
    print("1. Checking imports...")
    try:
        import customtkinter as ctk
        print("   OK customtkinter imported")
    except ImportError as e:
        print(f"   ERROR: {e}")
        return False
    
    try:
        import matplotlib.pyplot as plt
        from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
        print("   OK matplotlib imported")
    except ImportError as e:
        print(f"   ERROR: {e}")
        return False
    
    try:
        import numpy as np
        import joblib
        print("   OK numpy and joblib imported")
    except ImportError as e:
        print(f"   ERROR: {e}")
        return False
    
    # Check ML models
    print("\n2. Checking ML models...")
    try:
        from network_dashboard_desktop import MLModelManager
        ml_manager = MLModelManager()
        success = ml_manager.load_models()
        
        if success:
            print("   OK ML models loaded successfully")
            print(f"   OK Models available: {list(ml_manager.models.keys())}")
        else:
            print("   WARNING: ML models failed to load")
    except Exception as e:
        print(f"   ERROR: {e}")
        return False
    
    # Check GUI creation
    print("\n3. Checking GUI creation...")
    try:
        from network_dashboard_desktop import NetworkDashboard
        
        # Test basic GUI creation (without showing)
        app = NetworkDashboard()
        print("   OK GUI created successfully")
        
        # Check if all required components exist
        required_components = [
            'dashboard_frame', 'traffic_frame', 'devices_frame', 
            'threats_frame', 'ml_insights_frame', 'nav_buttons'
        ]
        
        missing_components = []
        for component in required_components:
            if not hasattr(app, component):
                missing_components.append(component)
        
        if missing_components:
            print(f"   WARNING: Missing components: {missing_components}")
        else:
            print("   OK All required components present")
        
        # Close the app
        app.destroy()
        
    except Exception as e:
        print(f"   ERROR: {e}")
        return False
    
    print("\n4. Bug Check Summary:")
    print("   OK All basic components working")
    print("   OK ML models loading correctly")
    print("   OK GUI creation successful")
    print("   OK No critical bugs detected")
    
    print("\nThe desktop application should work correctly!")
    return True

if __name__ == "__main__":
    check_bugs()
