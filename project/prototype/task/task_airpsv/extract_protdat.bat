@echo off
call _env.bat

set inpath=%1
set outpath=%2
for /f "delims=" %%i in ('dir /b %inpath%\*.dat') do (
    python -B %SRC_DIR%\prot_psv_dat.py d "%inpath%\%%i"  "%outpath%\%%i.png"
)