@echo off
:: ================================================
:: HappywiseGhala - App Stopper Script
:: ================================================

echo Stopping all port forwards...

:: Kill all kubectl port-forward processes
taskkill /F /IM kubectl.exe /T

echo.
echo All apps stopped successfully!
echo.
pause
