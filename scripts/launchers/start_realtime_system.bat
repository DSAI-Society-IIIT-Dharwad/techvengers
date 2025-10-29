@echo off
REM Real-Time Network Analyzer System Launcher for Windows
REM =====================================================
REM
REM This batch file launches the complete real-time network analysis system
REM including FastAPI backend, React frontend, and packet feeder.
REM
REM Prerequisites:
REM - Python 3.8+ with pip
REM - Node.js 16+ with npm
REM - Administrator privileges (for packet capture)
REM
REM Usage: start_realtime_system.bat

echo.
echo ========================================
echo Real-Time Network Traffic Analyzer
echo ========================================
echo.

REM Check if running as administrator
net session >nul 2>&1
if %errorLevel% == 0 (
    echo ✅ Running with administrator privileges
) else (
    echo ⚠️  Warning: Not running as administrator
    echo    Packet capture may require elevated privileges
    echo.
)

REM Check Python installation
python --version >nul 2>&1
if %errorLevel% neq 0 (
    echo ❌ Python not found. Please install Python 3.8+
    pause
    exit /b 1
)

REM Check Node.js installation
node --version >nul 2>&1
if %errorLevel% neq 0 (
    echo ❌ Node.js not found. Please install Node.js 16+
    pause
    exit /b 1
)

echo ✅ Prerequisites check passed
echo.

REM Install Python dependencies
echo 📦 Installing Python dependencies...
pip install -r requirements.txt
if %errorLevel% neq 0 (
    echo ❌ Failed to install Python dependencies
    pause
    exit /b 1
)

REM Install Node.js dependencies
echo 📦 Installing Node.js dependencies...
cd web-app\network-dashboard
if not exist node_modules (
    npm install
    if %errorLevel% neq 0 (
        echo ❌ Failed to install Node.js dependencies
        pause
        exit /b 1
    )
)
cd ..\..

echo ✅ Dependencies installed successfully
echo.

REM Check if ML models exist
if exist "data\trained_models\*.joblib" (
    echo ✅ ML models found
) else (
    echo ⚠️  No ML models found
    echo    The system will run without ML predictions
    echo    To train models, run: python src\analyzer.py
    echo.
)

REM Start the system using Python launcher
echo 🚀 Starting real-time network analyzer system...
echo.
echo This will start:
echo   - FastAPI backend (port 8000)
echo   - React frontend (port 3000)
echo   - Live packet feeder
echo.
echo Press Ctrl+C to stop all services
echo.

python web-app\launch_realtime_system.py

echo.
echo 🛑 System stopped
pause
