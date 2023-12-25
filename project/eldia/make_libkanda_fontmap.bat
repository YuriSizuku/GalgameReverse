if %DEVKITPRO%=="" (
    set DEVKITPRO=d:\Software\env\sdk\switchsdk
)
set PATH=%PATH%;%DEVKITPRO%\tools\bin;%DEVKITPRO%\devkitA64\bin
aarch64-none-elf-gcc src/kanda_switch_fontmap.c -nostdlib -nodefaultlibs -fPIC -shared -o asset/build/libkanda_fontmap.so -Os