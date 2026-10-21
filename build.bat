@echo off

setlocal

set "ROOT=%~dp0"
set "PS1=%ROOT%scripts\ghostlock.ps1"

set "PYEXE="
for /f "delims=" %%P in ('where python 2^>NUL') do if not defined PYEXE set "PYEXE=python"
if not defined PYEXE for /f "delims=" %%P in ('where py 2^>NUL') do if not defined PYEXE set "PYEXE=py -3"

if not defined PYEXE (
    echo ERROR: Python was not found on PATH.
    echo.
    echo Install Python 3 from https://www.python.org/downloads/windows/
    echo and make sure "python" or "py -3" works, then re-run build.bat.
    echo.
    echo The Android NDK is taken from the environment only, for example:
    echo     set ANDROID_NDK_HOME=D:\android-ndk\android-ndk-r30
    exit /b 9009
)

powershell -NoProfile -ExecutionPolicy Bypass -File "%PS1%" %*
exit /b %errorlevel%