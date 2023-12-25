@echo off
call _env.bat

echo ## convert png to gim
for /f "delims=" %%i in ('dir /b /s workflow2\3.edit\sys_png\*.png') do (
	echo %%i
	"%TOOL_DIR%\GimConv\GimConv.exe" "%%i" -o "%%~dpni" --format_style psp --format_endian little
)

echo ## fix some gim to index8 mode
"%TOOL_DIR%\GimConv\GimConv.exe" workflow2\3.edit\sys_png\sv.spc\sv.spc_20.gim.png -o sv.spc_20.gim --format_style psp --format_endian little --image_format index8
"%TOOL_DIR%\GimConv\GimConv.exe"  workflow2\3.edit\sys_png\sv.spc\sv.spc_25.gim.png -o sv.spc_25.gim --format_style psp --format_endian little --image_format index8
"%TOOL_DIR%\GimConv\GimConv.exe"  workflow2\3.edit\sys_png\sv.spc\sv.spc_44.gim.png -o sv.spc_44.gim --format_style psp --format_endian little --image_format index8

echo ## move gim and prepare to pack
xcopy /f /s /y workflow2\3.edit\sys_png\*.gim workflow2\4.post\sys_gim
del /s /q workflow2\3.edit\sys_png\*.gim
for /f "delims=" %%i in ('dir /b /s workflow2\4.post\sys_gim\*.gim') do (
	echo %%i
	move "%%i"  "%%~dpni.bin"
)

echo ## pack gim and compress to spc
for /f "delims=" %%i in ('dir /b /a:d workflow2\4.post\sys_gim') do (
	echo %%i
	python %SRC_DIR%\narcissus_psp_sn.py i workflow2\4.post\sys_gim\%%i workflow2\2.pre\sys_dec\%%i.dec workflow2\4.post\sys_dec\%%i.dec
	python %SRC_DIR%\narcissus_psp_lzss.py e workflow2\4.post\sys_dec\%%i.dec workflow2\4.post\sys\%%i
)

echo ## pack afs
copy /y workflow2\2.pre\sys.afs.txt workflow2\4.post\sys.afs.txt
pushd workflow2\4.post
"%TOOL_DIR%\AFSPacker_sjis.exe" -c .\sys "%RESULT_DIR%\USRDIR\sys.afs" .\sys.afs.txt
popd