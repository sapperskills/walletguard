@echo off
REM One wgbot pass (see docs\BOT.md). Register hourly from your own PowerShell:
REM   schtasks /create /tn "WalletGuard Bot" /tr "%~f0" /sc hourly /f
REM Stop: schtasks /delete /tn "WalletGuard Bot" /f   or create %LOCALAPPDATA%\WalletGuardBot\STOP
cd /d "%~dp0..\.."
if not exist "%LOCALAPPDATA%\WalletGuardBot" mkdir "%LOCALAPPDATA%\WalletGuardBot"
python -m tools.wgbot.forge --once >> "%LOCALAPPDATA%\WalletGuardBot\wgbot.log" 2>&1
