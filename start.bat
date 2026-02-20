@echo off
powershell -WindowStyle Hidden -Command "Start-Process -FilePath '%~dp0gitdock.exe' -WindowStyle Hidden -WorkingDirectory '%~dp0'"
