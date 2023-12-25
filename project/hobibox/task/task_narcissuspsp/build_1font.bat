@echo off
call _env.bat

python -B %SRC_DIR%\narcissus_psp_2bppfont.py c932 workflow\2.pre\font\font_sjis.tbl workflow\3.edit\default.ttf workflow\1.origin\font.bin workflow\4.post\font
move /y workflow\4.post\font\font_rebuild.bin %RESULT_DIR%\USRDIR\font.bin
copy /y workflow\4.post\font\font_chs.tbl workflow\4.post\narcissus_psp_chs.tbl