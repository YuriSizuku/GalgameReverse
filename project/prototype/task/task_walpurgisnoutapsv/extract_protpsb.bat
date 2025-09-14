@echo off
call _env.bat

set inpath=%1
set outpath=%2
for /f "delims=" %%i in ('dir /b %inpath%\*.psb') do ( 
    python -B %SRC_DIR%\prot_psv_psbtext.py "%inpath%\%%i" -o "%outpath%\%%~ni.txt"
)