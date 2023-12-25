@echo off
call _env.bat

for /f "delims=" %%i in ('dir /b %1\*.png') do (
    echo %%i
    python %SRC_DIR%\narcissus_psp_lbg.py f %1\%%i %2\%%i
)