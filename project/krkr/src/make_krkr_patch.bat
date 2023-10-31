clang krkr_patch.c -I./../windows/ -luser32 -lgdi32 -D _CRT_SECURE_NO_WARNINGS -target i686-pc-windows-msvc -shared -o ./build/krkr_patch.dll -Os
del .\build\*.lib
del .\build\*.exp