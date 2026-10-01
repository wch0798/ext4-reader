@echo off
cd /d "%~dp0"
chcp 65001 >nul

set "PY="
if exist "%LocalAppData%\Programs\Python\Python312\python.exe" set "PY=%LocalAppData%\Programs\Python\Python312\python.exe"
if not defined PY if exist "%LocalAppData%\Programs\Python\Python313\python.exe" set "PY=%LocalAppData%\Programs\Python\Python313\python.exe"
if not defined PY set "PY=python"

echo [1/3] 의존성 설치
"%PY%" -m pip install -r requirements.txt pyinstaller
if errorlevel 1 exit /b 1

echo [2/3] exe 빌드 (콘솔 없음)
"%PY%" -m PyInstaller --noconfirm Ext4Reader.spec
if errorlevel 1 exit /b 1

echo [3/3] 복사
copy /y "dist\Ext4Reader.exe" "Ext4Reader.exe" >nul
echo.
echo 완료: %~dp0Ext4Reader.exe
echo 물리 디스크는 우클릭 - 관리자 권한으로 실행 하세요.
pause
