@echo off
set bintext=.\..\bintext.py
for /f "delims=" %%i in ('dir /b %1') do (
    echo %%i
    python %bintext%  %1\%%i -o %1\%%i.txt %2 %3 %4 %5 %6 %7 %8 %9
)