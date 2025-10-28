@echo off
echo 🚀 Starting Network Traffic Analyzer Web Application
echo ==================================================

echo 📁 Current directory: %CD%
echo.

echo 🔍 Looking for project files...
if exist "web-app\api_server.py" (
    echo ✅ Found API server
    cd web-app
    echo 🚀 Starting Flask API Server...
    start "API Server" cmd /k "python api_server.py"
    timeout /t 3 /nobreak >nul
) else (
    echo ❌ API server not found in web-app directory
)

if exist "web-app\network-dashboard\package.json" (
    echo ✅ Found React app
    cd web-app\network-dashboard
    echo 🚀 Starting React Development Server...
    start "React App" cmd /k "npm start"
    timeout /t 5 /nobreak >nul
) else (
    echo ❌ React app not found in web-app\network-dashboard directory
)

echo.
echo 🌐 Applications should be starting...
echo 📊 API Server: http://localhost:5000
echo 🎨 React App: http://localhost:3000
echo.
echo Press any key to continue...
pause >nul
