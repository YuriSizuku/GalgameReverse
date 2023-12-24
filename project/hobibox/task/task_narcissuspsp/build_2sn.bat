@echo off
chcp 65001
call _env.bat

for /f "delims=" %%i in ('dir /b workflow\3.edit\sn_ftext\*.txt') do (
	echo %%i
	python -B %SRC_DIR%\narcissus_sntext.py i workflow\3.edit\sn_ftext\%%i workflow\2.pre\sn\%%~ni workflow\4.post\font\font_chs.tbl workflow\4.post\sn\%%~ni
)

:: rebuild sn_00.bin, this can not be longer
python %SRC_DIR%\compat\bintext_v580.py workflow\3.edit\sn_ftext\sn_00.bin.txt -p workflow\2.pre\sn\sn_00.bin --tbl workflow\4.post\font\font_chs.tbl -o workflow\4.post\sn\sn_00.bin --replace_map 〜:~ --padding_bytes 32

python -B %SRC_DIR%\narcissus_sn.py i workflow\4.post\sn workflow\2.pre\sn.bin.dec workflow\4.post\sn.bin.dec 
python -B %SRC_DIR%\narcissus_lzss.py e workflow\4.post\sn.bin.dec %RESULT_DIR%\USRDIR\sn.bin