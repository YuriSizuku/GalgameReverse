@echo off
call _env.bat

for /f "delims=" %%i in ('dir /b %1\*') do (
	echo %%i
	mkdir %1\%%~ni
	python %SRC_DIR%\narcissus_psp_sn.py e %1\%%i %1\%%~ni
)