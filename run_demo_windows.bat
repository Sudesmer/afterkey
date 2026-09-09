@echo off
setlocal
cd /d "%~dp0"
python -m afterkey doctor
if errorlevel 1 goto :fail
echo.
python -m afterkey demo
if errorlevel 1 goto :fail
echo.
echo AFTERKEY demo completed successfully.
pause
exit /b 0
:fail
echo.
echo AFTERKEY demo failed. Review the error above.
pause
exit /b 1
