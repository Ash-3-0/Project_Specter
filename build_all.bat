@echo off
setlocal
cd /d "%~dp0"
REM One build script for the desktop exe (SPECTER.exe) and the local web exe (SPECTER_Web.exe).
REM  - keys.json present  -> keys embedded in both exes + copied to dist\ (PERSONAL build, do not share the exes)
REM  - keys.json missing  -> exes built without keys (PUBLIC build, safe to publish)
echo ===== SPECTER build =====

taskkill /f /im SPECTER_Web.exe >nul 2>&1
taskkill /f /im SPECTER.exe >nul 2>&1

for %%F in (ioc_gui_neon.py ioc_web_neon.py specter.ico version_gui.txt version_web.txt check_keys.py) do (
  if not exist "%%F" (
    echo ERROR: %%F not found in this folder.
    goto :fail
  )
)

set "EMBED=0"
if exist keys.json (
  python check_keys.py || goto :fail
  set "EMBED=1"
  echo PERSONAL build: keys.json found, keys will be embedded. Do not share these exes.
) else (
  echo PUBLIC build: no keys.json, building without keys.
)

echo [1/4] Installing dependencies...
python -m pip install --upgrade pip pyinstaller customtkinter requests || goto :fail

echo [2/4] Cleaning old build...
if exist build rmdir /s /q build
if exist dist rmdir /s /q dist

echo [3/4] Building desktop exe (SPECTER.exe)...
if "%EMBED%"=="1" (
  python -m PyInstaller --noconfirm --onefile --windowed --name "SPECTER" --icon specter.ico --add-data "specter.ico;." --add-data "keys.json;." --version-file version_gui.txt --collect-all customtkinter ioc_gui_neon.py || goto :fail
) else (
  python -m PyInstaller --noconfirm --onefile --windowed --name "SPECTER" --icon specter.ico --add-data "specter.ico;." --version-file version_gui.txt --collect-all customtkinter ioc_gui_neon.py || goto :fail
)

echo [4/4] Building local web exe (SPECTER_Web.exe)...
if "%EMBED%"=="1" (
  python -m PyInstaller --noconfirm --onefile --name "SPECTER_Web" --icon specter.ico --add-data "keys.json;." --version-file version_web.txt ioc_web_neon.py || goto :fail
  copy /y keys.json dist\keys.json >nul
) else (
  python -m PyInstaller --noconfirm --onefile --name "SPECTER_Web" --icon specter.ico --version-file version_web.txt ioc_web_neon.py || goto :fail
)

echo.
echo DONE. Files in dist:
dir /b dist
pause
exit /b 0

:fail
echo.
echo BUILD STOPPED. Read the message above.
pause
exit /b 1
