@echo off
set encoding_org=sjis
set encoding_new=utf-16le
mkdir "%~dp1%encoding_new%"
for /f "delims=" %%i in ('dir /s /b /a -D %1') do (
    echo "%%i %encoding_org% -> %encoding_new%"
    python "%~dp0\text_encoding_covert.py" "%%i" %encoding_org% %encoding_new% "%~dp1%encoding_new%\%%~nxi"
)
pause