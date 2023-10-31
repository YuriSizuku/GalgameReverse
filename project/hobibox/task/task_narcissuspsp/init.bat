@echo off
call _env.bat

if not exist "%~dp0/workflow" (
  mklink /j workflow %WORKFLOW_DIR%
)

if not exist "%~dp0/workflow2" (
  mklink /j workflow2 %WORKFLOW2_DIR%
)