@echo off
call _env.bat

for /f "delims=" %%i in ('dir /b workflow2\3.edit\bg_png\*.png') do ( 
	echo %%i
	python %SRC_DIR%\narcissus_lbg.py invf workflow2\3.edit\bg_png\%%i workflow2\4.post\bg_png2\%%i
	python %SRC_DIR%\narcissus_lbg.py i workflow2\4.post\bg_png2\%%i workflow2\2.pre\bg_dec\%%~ni.dec workflow2\4.post\bg_dec\%%~ni.dec
	python %SRC_DIR%\narcissus_lzss.py e workflow2\4.post\bg_dec\%%~ni.dec workflow2\4.post\bg\%%~ni
	echo ##
)

copy /y workflow2\2.pre\bg.afs.txt workflow2\4.post\bg.afs.txt
pushd workflow2\4.post
"%TOOL_DIR%\AFSPacker_sjis.exe" -c .\bg "%RESULT_DIR%\USRDIR\bg.afs" .\bg.afs.txt
popd