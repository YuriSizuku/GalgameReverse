@echo off
call _env.bat

for /f "delims=" %%i in ('dir /b workflow\3.edit\texture_png\*.png') do (
	echo %%i
	python -B %SRC_DIR%\yomawari3_nltx.py i workflow\1.origin\texture\%%~ni workflow\3.edit\texture_png\%%i %RESULT_DIR%\romfs\Data\Texture\%%~ni
)