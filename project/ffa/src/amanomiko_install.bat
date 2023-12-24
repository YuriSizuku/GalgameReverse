@echo off
set CURPATH=%~dp0
::reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\G1WIN.EXE" /d "%~dp0G1WIN.EXE" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\G1WIN.EXE" /v "Path" /d "%CURPATH:~0,-1%" /f