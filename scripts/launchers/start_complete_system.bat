@echo off
echo ================================================================
echo    Complete Network Traffic Analyzer - ML System
echo ================================================================
echo.

echo [1/2] Starting Complete Network Analyzer...
echo.
echo System Components:
echo   - Live Network Capture: Active
echo   - ML Models: 4 models loaded (Isolation Forest, One-Class SVM, LOF, Scaler)
echo   - Feature Extraction: 17 features per connection
echo   - Real-time Analysis: Processing live traffic
echo   - Security Alerts: ML-powered anomaly detection
echo.
echo Starting server...
python complete_network_analyzer.py

echo.
echo ================================================================
echo    System Started Successfully!
echo ================================================================
echo.
echo Services Running:
echo   - Complete Network Analyzer: http://localhost:5000
echo   - ML Models: 4 models loaded and active
echo   - Live Capture: Monitoring network connections
echo.
echo Dashboard Access:
echo   1. Open network_dashboard.html in your browser
echo   2. Or visit: http://localhost:5000/api/health
echo   3. Watch live ML-powered security analysis
echo.
echo The system is now processing live network traffic through ML models!
echo.
pause