#!/usr/bin/env python3
"""
Alert Analysis Script
"""

import pandas as pd

def analyze_alerts():
    """Analyze streaming alerts."""
    try:
        df = pd.read_csv('streaming_alerts.csv')
        
        print("STREAMING ALERTS ANALYSIS")
        print("=" * 50)
        print(f"Total alerts generated: {len(df)}")
        
        print(f"\nAlert types:")
        alert_types = df['alert_type'].value_counts()
        for alert_type, count in alert_types.items():
            print(f"  - {alert_type}: {count}")
        
        print(f"\nRisk levels:")
        risk_levels = df['risk_level'].value_counts()
        for risk_level, count in risk_levels.items():
            print(f"  - {risk_level}: {count}")
        
        print(f"\nModels detecting anomalies:")
        # Extract model names from reason column
        model_names = df['reason'].str.split().str[0].value_counts()
        for model, count in model_names.items():
            print(f"  - {model}: {count} detections")
        
        print(f"\nAnomaly score statistics:")
        print(f"  - Average score: {df['anomaly_score'].mean():.3f}")
        print(f"  - Min score: {df['anomaly_score'].min():.3f}")
        print(f"  - Max score: {df['anomaly_score'].max():.3f}")
        
        print(f"\nWindow analysis:")
        print(f"  - Total windows processed: {df['window_id'].max()}")
        print(f"  - Average packets per alert: {df['packet_count'].mean():.1f}")
        
    except Exception as e:
        print(f"Error analyzing alerts: {e}")

if __name__ == "__main__":
    analyze_alerts()
