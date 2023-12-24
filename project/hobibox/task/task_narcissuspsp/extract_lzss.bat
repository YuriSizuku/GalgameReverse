@echo off
call _env.bat

for /f "delims=" %%i in ('dir /b %1\*') do (
	echo %%i
	python %SRC_DIR%\narcissus_lzss.py d %1\%%i %1\%%i.dec
)