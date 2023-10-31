mkdir asset/build
clang -target i686-pc-windows-msvc src/ons_decryptnt3.c -o asset/build/ons_decryptnt3.exe -D_CRT_SECURE_NO_WARNINGS