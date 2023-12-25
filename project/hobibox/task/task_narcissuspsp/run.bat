@echo off
call _env.bat

echo %GAME_LAUNCHER%
start %GAME_LAUNCHER% "%GAME_DIR%"