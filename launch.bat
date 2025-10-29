@echo off
echo ============================================================
echo NETWORK SECURITY DASHBOARD
echo ============================================================
echo Organized Workspace Launcher
echo.

cd desktop-app
if exist "start_desktop_dashboard.py" (
    echo Starting Desktop Application...
    echo Location: desktop-app/start_desktop_dashboard.py
    echo.
    python start_desktop_dashboard.py
) else (
    echo Desktop application not found!
    echo Expected location: desktop-app/start_desktop_dashboard.py
    echo.
    echo Available options:
    echo 1. Run desktop app: cd desktop-app ^&^& python start_desktop_dashboard.py
    echo 2. Run ML tests: cd tests/ml-tests ^&^& python test_anomaly_detection.py
    echo 3. View documentation: docs/guides/
    echo 4. Check utilities: scripts/utilities/
)

pause
