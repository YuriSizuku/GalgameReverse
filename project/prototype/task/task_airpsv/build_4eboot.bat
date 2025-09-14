@echo off
call _env.bat

::python -B %SRC_DIR%\compat\bintext_v400.py -p %WORKFLOW_DIR%\1.origin\eboot_mai.bin -o %RESULT_DIR%\eboot.bin --tbl %WORKFLOW_DIR%\4.post\air_psv_chs.tbl  %WORKFLOW_DIR%\3.edit\eboot.bin.txt

python -B %SRC_DIR%\compat\bintext_v400.py -p %WORKFLOW_DIR%\1.origin\eboot.bin.elf -o  %WORKFLOW_DIR%\4.post\eboot.bin.elf --tbl %WORKFLOW_DIR%\4.post\air_psv_chs.tbl  %WORKFLOW_DIR%\3.edit\eboot.bin.elf.txt

copy /y %WORKFLOW_DIR%\1.origin\eboot.bin %WORKFLOW_DIR%\4.post\eboot.bin
"%TOOL_DIR%\vita-elf-inject.exe" %WORKFLOW_DIR%\4.post\eboot.bin %WORKFLOW_DIR%\4.post\eboot.bin.elf
move /y %WORKFLOW_DIR%\4.post\eboot.bin %WORKFLOW_DIR%\5.result\eboot.bin