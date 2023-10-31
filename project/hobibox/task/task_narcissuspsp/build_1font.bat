@echo off
call _env.bat

python -B %SRC_DIR%\Narcissus_2bppfont.py c workflow\2.pre\font\font_sjis.tbl workflow\3.edit\default.ttf workflow\1.origin\font.bin workflow\4.post\font
move /y workflow\4.post\font\font_rebuild.bin %RESULT_DIR%\USRDIR\font.bin