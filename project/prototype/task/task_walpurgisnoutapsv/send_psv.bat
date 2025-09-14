@echo off
call _env.bat

set appid=PCSG00768
::set ipaddr=192.168.137.212
echo ip="%ipaddr%"

:: /ux0:/data/savegames/PCSG00768
:: /ux0:/rePatch/PCSG00768
curl --ftp-method nocwd -T %WORKFLOW_DIR%/5.result/eboot.bin ftp://%ipaddr%:1337/ux0:/rePatch/%appid%/eboot.bin
curl --ftp-method nocwd -T %WORKFLOW_DIR%/5.result/psvscr.tbl ftp://%ipaddr%:1337/ux0:/rePatch/%appid%/psvscr.tbl
curl --ftp-method nocwd -T %WORKFLOW_DIR%/5.result/psvscr00.pak ftp://%ipaddr%:1337/ux0:/rePatch/%appid%/psvscr00.pak
curl --ftp-method nocwd -T %WORKFLOW_DIR%/5.result/psvsys.tbl ftp://%ipaddr%:1337/ux0:/rePatch/%appid%/psvsys.tbl
curl --ftp-method nocwd -T %WORKFLOW_DIR%/5.result/psvsys00.pak ftp://%ipaddr%:1337/ux0:/rePatch/%appid%/psvsys00.pak