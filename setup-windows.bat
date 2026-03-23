@echo off
echo ========================================
echo Healthcare GenAI Security Setup
echo ========================================
echo.

echo Checking prerequisites...
echo.

REM Check Python
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ❌ Python not found! Please install Python 3.9+ from https://python.org
    echo.
    pause
    exit /b 1
) else (
    echo ✅ Python found
)

REM Check Node.js
node --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ❌ Node.js not found! Please install Node.js 18+ from https://nodejs.org
    echo.
    pause
    exit /b 1
) else (
    echo ✅ Node.js found
)

echo.
echo Installing dependencies...
echo.

echo Installing Python dependencies...
cd backend
pip install -r requirements.txt
if %errorlevel% neq 0 (
    echo ❌ Failed to install Python dependencies
    pause
    exit /b 1
)
cd ..

echo Installing Node.js dependencies...
cd frontend
npm install
if %errorlevel% neq 0 (
    echo ❌ Failed to install Node.js dependencies
    pause
    exit /b 1
)
cd ..

echo.
echo ========================================
echo ✅ Setup Complete!
echo ========================================
echo.
echo Next steps:
echo 1. Install PostgreSQL from https://postgresql.org/download/windows/
echo 2. Install Redis from https://github.com/microsoftarchive/redis/releases
echo 3. Create .env file with your configuration
echo 4. Start the application:
echo    - Terminal 1: cd backend ^& uvicorn main:app --reload
echo    - Terminal 2: cd frontend ^& npm run dev
echo.
echo For detailed instructions, see SETUP.md
echo.
pause 