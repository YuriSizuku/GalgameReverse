@echo off
set encoding_org=sjis
set encoding_new=gbk
mkdir "%~1\%encoding_new%"
for /f "delims=" %%i in ('dir /b /a -D %1') do (
    echo %%i
    python "%~dp0\text_encoding_covert.py" "%~1\%%i" %encoding_org% %encoding_new% "%~1\%encoding_new%\%%i"
)
pause