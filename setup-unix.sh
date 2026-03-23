#!/bin/bash
echo "========================================"
echo "Healthcare GenAI Security Setup"
echo "========================================"
echo

echo "Checking prerequisites..."
echo

# Check Python
if ! command -v python3 &> /dev/null; then
    echo "❌ Python3 not found! Please install Python 3.9+"
    echo "   macOS: brew install python3"
    echo "   Ubuntu: sudo apt-get install python3 python3-pip"
    exit 1
else
    echo "✅ Python3 found"
fi

# Check Node.js
if ! command -v node &> /dev/null; then
    echo "❌ Node.js not found! Please install Node.js 18+"
    echo "   macOS: brew install node"
    echo "   Ubuntu: sudo apt-get install nodejs npm"
    exit 1
else
    echo "✅ Node.js found"
fi

echo
echo "Installing dependencies..."
echo

echo "Installing Python dependencies..."
cd backend
pip3 install -r requirements.txt
if [ $? -ne 0 ]; then
    echo "❌ Failed to install Python dependencies"
    exit 1
fi
cd ..

echo "Installing Node.js dependencies..."
cd frontend
npm install
if [ $? -ne 0 ]; then
    echo "❌ Failed to install Node.js dependencies"
    exit 1
fi
cd ..

echo
echo "========================================"
echo "✅ Setup Complete!"
echo "========================================"
echo
echo "Next steps:"
echo "1. Install PostgreSQL:"
echo "   macOS: brew install postgresql"
echo "   Ubuntu: sudo apt-get install postgresql postgresql-contrib"
echo "2. Install Redis:"
echo "   macOS: brew install redis"
echo "   Ubuntu: sudo apt-get install redis-server"
echo "3. Create .env file with your configuration"
echo "4. Start the application:"
echo "   - Terminal 1: cd backend && uvicorn main:app --reload"
echo "   - Terminal 2: cd frontend && npm run dev"
echo
echo "For detailed instructions, see SETUP.md"
echo 