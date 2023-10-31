@echo off
call _env.bat

copy /y workflow\3.edit\default.ttf %RESULT_DIR%\romfs\Data\Font\ArmedLemon.TTF
copy /y workflow\3.edit\default.ttf %RESULT_DIR%\romfs\Data\Font\crayon_1-1.ttf
copy /y workflow\3.edit\default.otf %RESULT_DIR%\romfs\Data\Font\FOT-UtrilloPro-M.otf
copy /y workflow\3.edit\default.ttc %RESULT_DIR%\romfs\Data\Font\msgothic.ttc