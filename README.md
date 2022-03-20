# GalgameReverse

Some methods for extracting or importing in Galgame,  

as well as some methods for CHS localization.  

util tools are moved to https://github.com/YuriSizuku/ReverseUtil 



> onscripter

* `extract_nt3.c`,  *.nt3 script extract

> krkr

* `krkr_patch.c`, make `krkr_patch.dll` for change locale and redirect CHSPATCH 
* ` krkr_sjis2utf16bom` , batch convert `sjis` files to `utf-16le-bom` format
* `sdhime_xp3enc.cpp`,  for make encrypted xp3 files
* `sdhime_krkrpatch`, support for  `つばさの丘の姫王` chs localization

> artemis

* `artemis_pf8.py`,  pf8 format archive pack and unpack

> tyrano

* `tyrano_extractexe.c` A tool to extract tyrano build-in exe files
* `qbit_text.py` Extract and insert text for translate the game  `Q-bit_キグルミキノコ`

> azsystem

* `azsystem_tool`, not finished yet

* `lamune_hook.js`, decrypt the *.asb and *.tbl files

* `lamune_patch.c`, for `ラムネ`chs support, semi-dynamic framework

> majiro

* `winterpolaris_hook.js` dump `mjo` and analyze `majiro` in `winter polaris` game
* `winterpolaris_patch.c`  Majirov3 dynamic hook CHSPATCH framework code example

> yuris

* `akaihana_yurispatch.c`, gbk support  for game `越えざるは红い花 remaster`

> criware

* `xtx_font.py`, `xtx` font decode and encode, for `祝姫`   
* `iwaihime_pc_decrypt.c`,  `sn.bin` decode

> prototype

* `air_psv_dat.py`, dat picture（RGBA8888, RGB888, delta encoding,color panel） decode and encode
* `air_psv_psbtext.py`, extract and import the text to PSV `air`, can be longer than origin
* `air_psv_4bppfnt.py`, for building the psv air 4bpp font

> ig

* `redirect_ig.c`, redirect the files to `xxx_chs` for separate CHSPATCH, tested in `天ノ少女`　`Innocent Gray`

> cycrose

* `baranoki_psp_zp.py`, ``baranoki_psp_pk``, support *.zp, *.pk file for `薔薇ノ木ニ薔薇ノ花咲ク`
* `baranoki_psp_vmc.py`, `baranoki_psp_pktext.py`, text support
* `baranoki_psp_fontfnt.py`, `baranoki_psp_fontp.py`, tile font support
* `baranoki_psp_boot.py`, rebuild the boot for fixing size buffer

> gss

* 月影の鎖 -錯乱パラノイア PSP, PSV see, my [pull request](https://github.com/morkt/GARbro/pull/435) in my forked GARBRO

> Bruns

* `bruns_decrypt.c` , to decrypt  `EENZ` file,  `解体挿入新書` tested 

