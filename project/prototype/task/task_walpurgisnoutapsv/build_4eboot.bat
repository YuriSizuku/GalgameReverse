@echo off
call _env.bat

set PATH="%TOOL_DIR%";%PATH%

copy /y  %WORKFLOW_DIR%\1.origin\eboot.bin "%RESULT_DIR%\eboot.bin"
python -B %SRC_DIR%\compat\bintext_v400.py -p  %WORKFLOW_DIR%\1.origin\eboot.bin.elf -o  %WORKFLOW_DIR%\4.post\eboot.bin.elf --tbl  %WORKFLOW_DIR%\4.post\walpurgisnouta_psv_chs.tbl   %WORKFLOW_DIR%\3.edit\eboot.bin.elf.txt
vita-elf-inject "%RESULT_DIR%\eboot.bin"  %WORKFLOW_DIR%\4.post\eboot.bin.elf