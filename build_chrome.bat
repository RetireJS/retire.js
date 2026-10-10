@echo off
setlocal
cd /d "%~dp0"
cd node
call npm install
if errorlevel 1 exit /b 1
call npm run build
if errorlevel 1 exit /b 1
cd ..\chrome\build
call npm install
if errorlevel 1 exit /b 1
call npm run build
if errorlevel 1 exit /b 1
echo Built chrome/extension, chrome/extension-no-func, and dist/firefox.
