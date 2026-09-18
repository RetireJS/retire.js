@echo off
setlocal
cd /d "%~dp0"
cd node
call npm ci --no-audit --no-fund
if errorlevel 1 exit /b 1
call npm run build
if errorlevel 1 exit /b 1
cd ..\chrome\build
call npm ci --no-audit --no-fund
if errorlevel 1 exit /b 1
call npm run build
if errorlevel 1 exit /b 1
echo Built Chrome, Chrome no-func, and Firefox packages in dist.
