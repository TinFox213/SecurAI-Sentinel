# 🚀 SecurAI Sentinel v2.0 - Quick Launch Script
# This script starts both the backend server and frontend simultaneously

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "   SecurAI Sentinel v2.0 Launcher" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Check if Node.js is installed
$nodeVersion = node --version 2>$null
if (-not $nodeVersion) {
    Write-Host "❌ ERROR: Node.js is not installed!" -ForegroundColor Red
    Write-Host "   Please install Node.js from: https://nodejs.org/" -ForegroundColor Yellow
    exit 1
}

Write-Host "✅ Node.js detected: $nodeVersion" -ForegroundColor Green
Write-Host ""

# Check if dependencies are installed
Write-Host "📦 Checking dependencies..." -ForegroundColor Yellow

if (-not (Test-Path "node_modules")) {
    Write-Host "⚠️  Frontend dependencies not found. Installing..." -ForegroundColor Yellow
    npm install
}

if (-not (Test-Path "server/node_modules")) {
    Write-Host "⚠️  Backend dependencies not found. Installing..." -ForegroundColor Yellow
    Set-Location server
    npm install
    Set-Location ..
}

Write-Host "✅ All dependencies installed" -ForegroundColor Green
Write-Host ""

# Start the application
Write-Host "🚀 Launching SecurAI Sentinel v2.0..." -ForegroundColor Cyan
Write-Host ""
Write-Host "📡 Backend will run on: http://localhost:3001" -ForegroundColor Gray
Write-Host "🌐 Frontend will run on: http://localhost:3000" -ForegroundColor Gray
Write-Host ""
Write-Host "⚠️  To stop the servers, press Ctrl+C" -ForegroundColor Yellow
Write-Host ""
Write-Host "Starting in 3 seconds..." -ForegroundColor Gray
Start-Sleep -Seconds 3

# Start backend server in background
Write-Host "🔧 Starting backend server..." -ForegroundColor Cyan
$backendJob = Start-Job -ScriptBlock {
    Set-Location $using:PWD
    Set-Location server
    npm start
}

# Wait a moment for server to start
Start-Sleep -Seconds 2

# Start frontend
Write-Host "🎨 Starting frontend..." -ForegroundColor Cyan
Write-Host ""
Write-Host "========================================" -ForegroundColor Green
Write-Host "   ✅ READY! Open browser to:" -ForegroundColor Green
Write-Host "   http://localhost:3000" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host ""

# Start frontend (this will keep terminal open)
npm run dev

# Cleanup: Stop backend when frontend exits
Write-Host ""
Write-Host "🛑 Shutting down backend server..." -ForegroundColor Yellow
Stop-Job -Job $backendJob
Remove-Job -Job $backendJob
Write-Host "✅ Shutdown complete" -ForegroundColor Green
