@echo off
chcp 65001
call _env.bat

python -B %SRC_DIR%\compat\bintext_v580.py workflow\3.edit\EBOOT.BIN.txt -p workflow\1.origin\EBOOT.BIN --tbl workflow\4.post\narcissus_psp_chs.tbl -o %RESULT_DIR%\SYSDIR\EBOOT.BIN --replace_map ·:・
copy /y %RESULT_DIR%\SYSDIR\EBOOT.BIN %RESULT_DIR%\SYSDIR\BOOT.BIN