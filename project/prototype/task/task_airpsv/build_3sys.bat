@echo off
call _env.bat

echo ## copy font
xcopy /y %WORKFLOW_DIR%\2.pre\\psvsys\ %WORKFLOW_DIR%\4.post\psvsys\ >NUL
copy /y %WORKFLOW_DIR%\4.post\mdnp32_gb2312.fnt %WORKFLOW_DIR%\4.post\psvsys\148_3E3A382.dat
copy /y %WORKFLOW_DIR%\4.post\mdnp32_gb2312.fnt %WORKFLOW_DIR%\4.post\psvsys\149_9B6709B.dat
copy /y %WORKFLOW_DIR%\4.post\mdnp32_gb2312.fnt %WORKFLOW_DIR%\4.post\psvsys\150_10DF753.dat
copy /y %WORKFLOW_DIR%\4.post\mdnp32_gb2312.fnt %WORKFLOW_DIR%\4.post\psvsys\151_8F997CC.dat

echo ## build chs dat
for /f "delims=" %%i  in ('dir /b %WORKFLOW_DIR%\3.edit\psvsys_png\*.png') do (
    echo %%i
    python -B %SRC_DIR%\prot_psv_dat.py e %WORKFLOW_DIR%\3.edit\psvsys_png\%%i  %WORKFLOW_DIR%\2.pre\psvsys\%%~ni %WORKFLOW_DIR%\4.post\psvsys\%%~ni
)

echo ## make pak
"%TOOL_DIR%\prot_tblpak.exe" "%WORKFLOW_DIR%\4.post\psvsys"  "%WORKFLOW_DIR%\5.result\psvsys.tbl"