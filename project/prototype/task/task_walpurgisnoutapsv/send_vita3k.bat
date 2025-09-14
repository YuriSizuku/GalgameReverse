@echo off
call _env.bat

xcopy /y /s %WORKFLOW_DIR%\5.result\* %GAME_DIR%
