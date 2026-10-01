@echo off
net session >nul 2>&1
if %errorLevel%==0 goto :run
powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
exit /b

:run
cd /d "%~dp0"
chcp 65001 >nul

if exist "%~dp0Ext4Reader.exe" (
  start "" "%~dp0Ext4Reader.exe"
  exit /b 0
)

title EXT4 Reader 로그
set "PYTHONUNBUFFERED=1"
set "PYTHONPATH=%~dp0"
set "EXT4READER_HOST=1"

set "PY="
if exist "%LocalAppData%\Programs\Python\Python312\Ext4Reader.exe" set "PY=%LocalAppData%\Programs\Python\Python312\Ext4Reader.exe"
if not defined PY if exist "%LocalAppData%\Programs\Python\Python312\python.exe" set "PY=%LocalAppData%\Programs\Python\Python312\python.exe"
if not defined PY if exist "%LocalAppData%\Programs\Python\Python313\python.exe" set "PY=%LocalAppData%\Programs\Python\Python313\python.exe"

if not defined PY (
  echo 설치된 Python 3.12를 찾지 못했습니다.
  echo Microsoft Store용 python 바로가기는 사용할 수 없습니다.
  echo https://www.python.org/downloads/
  pause
  exit /b 1
)

"%PY%" -m ext4reader
if %errorlevel% neq 0 pause
