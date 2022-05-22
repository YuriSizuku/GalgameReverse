# GalgameReverse

Some methods for extracting or importing in Galgame,  
as well as some methods for CHS localization.  
util tools are moved to https://github.com/YuriSizuku/ReverseUtil

## onscripter

* `extract_nt3.c`,  *.nt3 script extract  

## krkr

* `krkr_patch.c`, make `krkr_patch.dll` for change locale and redirect CHSPATCH  
* `krkr_sjis2utf16bom` , batch convert `sjis` files to `utf-16le-bom` format  

> つばさの丘の姫王

* `sdhime_xp3enc.cpp`,  for make encrypted xp3 files  
* `sdhime_krkrpatch`, support for  `つばさの丘の姫王` chs localization  

## artemis

* `artemis_pf8.py`,  pf8 format archive pack and unpack  

## tyrano

* `tyrano_extractexe.c` A tool to extract tyrano build-in exe files  

> Q-bit_キグルミキノコ (android)  

* `qbit_text.py` Extract and insert text for translate the game  `Q-bit_キグルミキノコ`  

## azsystem

* `azsystem_tool`, not finished yet  

> ラムネ

* `lamune_hook.js`, decrypt the `*.asb` and `*.tbl` files  
* `lamune_patch.c`, for `ラムネ`chs support, semi-dynamic framework  

## majiro

> winterpolaris

* `winterpolaris_hook.js` dump `mjo` and analyze `majiro` in `winter polaris` game  
* `winterpolaris_patch.c`  Majirov3 dynamic hook CHSPATCH framework code example  

## yuris

> 越えざるは红い花 remaster

* `akaihana_yurispatch.c`, gbk support  for game `越えざるは红い花 remaster`  

## criware

> 祝姫

* `xtx_font.py`, `xtx` font decode and encode, for `祝姫`  
* `iwaihime_pc_decrypt.c`,  `sn.bin` decode  

## ig (innocent gray)

> 天ノ少女

* `redirect_ig.c`, redirect the files to `xxx_chs` for separate CHSPATCH, tested in `天ノ少女`　`Innocent Gray`  

## hibiki

> Natrual Vacation

* `hibiki_text_ks.py`, export and import game text for ftext format
* `hibiki_rename_picture.py`, rename all the picture name to crc32, to avoid sjis file name problem

## Bruns

> 解体挿入新書

* `bruns_decrypt.c` , to decrypt  `EENZ` file,  `解体挿入新書` tested  

## LiveMaker

> アイするキミの居場所

* `aikimi_loader.c`, a loader to dynamic inject DLL to the game
* `aikimi_patch.c`, patch the game dynamiclly to support `GBK` text

## nippon1

> 夜廻3 (switch)

* `ykcmp.py`, An implementation in python to parse ykcmp compression.  
* `yomawari3_nltx.py`, deal with switch swizzle texture in nltx file.

## prototype

> air (psv)

* `air_psv_dat.py`, dat picture（RGBA8888, RGB888, delta encoding,color panel） decode and encode  
* `air_psv_psbtext.py`, extract and import the text to PSV `air`, can be longer than origin  
* `air_psv_4bppfnt.py`, for building the psv air 4bpp font  

## cycrose

> 薔薇ノ木ニ薔薇ノ花咲ク (psp)

* `baranoki_psp_zp.py`, ``baranoki_psp_pk``, support `*.zp`, `*.pk` file for `薔薇ノ木ニ薔薇ノ花咲ク`  
* `baranoki_psp_vmc.py`, `baranoki_psp_pktext.py`, text support  
* `baranoki_psp_fontfnt.py`, `baranoki_psp_fontp.py`, tile font support  
* `baranoki_psp_boot.py`, rebuild the boot for fixing size buffer  

## gss

> 月影の鎖 -錯乱パラノイア(psp, psv)

* `gss_arc.cs`, for `月影の鎖 -錯乱パラノイア` PSP, PSV see, my [pull request](https://github.com/morkt/GARbro/pull/435) in my forked GARBRO 

## if (idea factory)

> ジュエリック・ナイトメア (psp)

* `Jewelic_UF.py`,  building the UF tile font,  for`Jewelic Nightmare (ジュエリック・ナイトメア)`  
* `Jewelic_STCM2L.py`,  converting the `ftext` (by [bintext.py](https://github.com/YuriSizuku/ReverseUtil/blob/master/script/bintext.py)) to STCM2Ltool format (made by [STCM2L_import.py](https://github.com/Yggdrasill-Moe/Helheim/blob/master/%E5%8D%81%E9%AC%BC%E4%B9%8B%E7%BB%8A/STCM2L_import.py)),  for`Jewelic Nightmare (ジュエリック・ナイトメア)`  