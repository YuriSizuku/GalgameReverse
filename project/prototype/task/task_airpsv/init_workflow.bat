@echo off
call _env.bat

echo ## prepare psvscr files
if not exist workflow\2.pre\psvscr\ (
    mkdir workflow\2.pre\psvscr
    "%TOOL_DIR%\prot_tblpak.exe" "%~dp0\workflow\1.origin\psvscr.tbl" "%~dp0\workflow\2.pre\psvscr"
)
if not exist workflow\3.edit\psvscr_ftext\ ( 
    mkdir workflow\3.edit\psvscr_ftext
    call extract_protpsb.bat workflow\2.pre\psvscr workflow\3.edit\psvscr_ftext
)

echo ## prepare psvsys file
if not exist workflow\2.pre\psvsys\ ( 
    mkdir workflow\2.pre\psvsys
    "%TOOL_DIR%\prot_tblpak.exe" "%~dp0\workflow\1.origin\psvsys.tbl" "%~dp0\workflow\2.pre\psvsys"
)
if not exist workflow\3.edit\psvsys_png\ ( 
    mkdir workflow\3.edit\psvsys_png
	call extract_protdat.bat "%~dp0\workflow\2.pre\psvsys" "%~dp0\workflow\3.edit\psvsys_png"
)