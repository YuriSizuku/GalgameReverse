@echo off
call _env.bat

for /f "delims=" %%i in ('dir /b %1\*.lbg') do (
	echo %%i
	python %SRC_DIR%\narcissus_psp_lbg.py e %1\%%i %1\%%~ni.png
)