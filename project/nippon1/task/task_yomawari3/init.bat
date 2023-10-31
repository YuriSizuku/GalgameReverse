@echo off
call _env.bat

if not exist "%~dp0/workflow" (
  mklink /j workflow %WORKFLOW_DIR%
)