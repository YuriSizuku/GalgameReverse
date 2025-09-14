@echo off
call _env.bat

python -B %SRC_DIR%\prot_psv_4bppfnt.py b936 %WORKFLOW_DIR%\1.origin\mdnp32.fnt %WORKFLOW_DIR%\3.edit\default.ttf %WORKFLOW_DIR%\4.post\mdnp32_gb2312.fnt
copy /y %WORKFLOW_DIR%\4.post\mdnp32_gb2312.tbl  %WORKFLOW_DIR%\4.post\air_psv_chs.tbl
del /q %WORKFLOW_DIR%\3.edit\default.ttf.png