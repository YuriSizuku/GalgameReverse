@echo off
call _env.bat

echo ## import psvscr text
xcopy /y %WORKFLOW_DIR%\2.pre\psvscr %WORKFLOW_DIR%\4.post\psvscr
for /f "delims=" %%i in ('dir /b %WORKFLOW_DIR%\3.edit\psvscr_ftext\*.txt') do (
    echo %%i 
    python -B %SRC_DIR%\prot_psv_psbtext.py -p %WORKFLOW_DIR%\2.pre\psvscr\%%~ni.psb -o %WORKFLOW_DIR%\4.post\psvscr\%%~ni.psb --tbl %WORKFLOW_DIR%\4.post\walpurgisnouta_psv_chs.tbl %WORKFLOW_DIR%\3.edit\psvscr_ftext\%%i --disable_longer
)

echo ## rebuild pak, tbl file
"%TOOL_DIR%\prot_tblpak.exe" "%WORKFLOW_DIR%\4.post\psvscr"  "%RESULT_DIR%\psvscr.tbl"