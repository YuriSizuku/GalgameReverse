@echo off
call _env.bat

for /f "delims=" %%i in ('dir /b %1\\*.nltx') do (
	echo %%i
	python -B %SRC_DIR%\yomawari3_nltx.py e "%1\\%%i" "%1\\%%i.png"
)