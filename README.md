# GalgameReverse

Some method of extracting or packing Galgame.
With the list:

> My UTIL scripts

* `binary_text.py`, A binary text tool for text exporting and importing, checking 
* `font_util.py`, UTILS for extracting, building tile font, or generating font picture.
* `listmagic.py`, list the files magic to analyze
* `texture.py`, something about texture and picture convert

> windows tools

* `injectdll.py` , static inject  `dll` to a `exe`
* `win_console.js`,  Allocate a console for game
* `win_file.js` , view information for both `CreateFile`, `ReadFile`, `WriteFile`, `fopen`,`fread`, `fwrite`
* `win_redirect.js`, redirect font, codepage, and paths in games
* `win_hook.cpp`, `win_hook.h` dynamic hook functions, such as IAT hook, inline hook

> KRKR tools

* `krkr_patch.c`, make `krkr_patch.dll` for change locale and redirect CHSPATCH
*  ` krkr_sjis2utf16bom` , batch convert `sjis` files to `utf-16le-bom` format

> Onscriptor

* `extract_nt3.c`,  nt3 script extract

> Artemis

* `pf8tool.py`,  pf8 format archive pack and unpack

> Criware

* `xtx_font.py`, `xtx` font decode and encode
* `iwaihime_pc_decrypt.c`,  `sn.bin` decode

> Prototype

* `prot_dat.py`, dat picture（RGBA8888, RGB888, delta encoding,color panel） decode and encode
* `airpsv_text.py`, extract and import the text to PSV air, can be longer than origin

> Gss

* 月影の鎖 -錯乱パラノイア PSP, PSV see, my [pull request](https://github.com/morkt/GARbro/pull/435) in my forked GARBRO 

> InnocentGray

* `redirect_ig.c`, redirect the files to `xxx_chs` for separate CHSPATCH

> Bruns

* `bruns_decrypt.c` , to decrypt  `EENZ` file,  `DustmaniaGrotesque` tested 

> Majiro

* `winterpolaris_hook.js` dump `mjo` and analyze `majiro` in `winterpolaris` game

* `winterpolaris_hook.c`  Majirov3 dynamic hook CHSPATCH framework code example

