@echo off
call _env.bat

:: seems that this works on switch, but crash on yuzuea 3938
start %GAME_LAUNCHER% -g "%GAME_ROM%"