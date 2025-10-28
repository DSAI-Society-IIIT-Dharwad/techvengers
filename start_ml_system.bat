@echo off
echo ================================================================
echo    Live Network Traffic Analyzer - ML-Powered System
echo ================================================================
echo.

echo [1/3] Stopping any existing servers...
taskkill /f /im python.exe 2>nul
timeout /t 2 /nobreak >nul

echo [2/3] Starting Fixed Live Network Analyzer with ML Models...
echo.
echo This system will:
echo   - Load your trained ML models (Isolation Forest, One-Class SVM, LOF)
echo   - Monitor live network connections
echo   - Extract all 17 required features
echo   - Analyze traffic with ML models
echo   - Generate real-time security alerts
echo.
echo Starting server...
start cmd /k "python fixed_live_analyzer.py"

echo [3/3] Waiting for server to start...
timeout /t 5 /nobreak >nul

echo.
echo ================================================================
echo    System Started Successfully!
echo ================================================================
echo.
echo Services Running:
echo   - Fixed Live Network Analyzer: http://localhost:5000
echo   - ML Models: Loaded and Active
echo   - Feature Extraction: 17 features per connection
echo.
echo Features:
echo   - Real-time network monitoring
echo   - ML-powered anomaly detection
echo   - Live security alerts with risk scoring
echo   - Interactive dashboard
echo.
echo To view the dashboard:
echo   1. Open ml_security_dashboard.html in your browser
echo   2. Click 'Start Capture' to begin monitoring
echo   3. Watch for ML-generated security alerts
echo.
echo The system is now processing live network traffic through your ML models!
echo.
pause
