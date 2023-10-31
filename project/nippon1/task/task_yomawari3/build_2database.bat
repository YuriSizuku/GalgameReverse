@echo off
chcp 65001
call _env.bat

for /f "delims=" %%i in ('dir /b workflow\3.edit\database_ftext\*.txt') do (
	echo %%i
	python -B %SRC_DIR%\compat\bintext_v580.py  workflow\3.edit\database_ftext\%%i  -p workflow\1.origin\database\%%~ni -o %RESULT_DIR%\romfs\Data\Database\%%~ni -e utf8 --padding_bytes 00 --replace ・:.
)