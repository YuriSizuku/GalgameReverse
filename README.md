# GalgameReverse

Some methods for galgame engine reverse and localization support.  
Util tools are moved to [ReverseUtil](https://github.com/YuriSizuku/ReverseUtil).

## (1) Cross galgame

### onscripter

* `extract_nt3.c`,  extract *.nt3 script  
* `nscript_patch.c`, support gbk, redirect `*.dat`, `*.arc` file

### krkr

* `krkr_patch.c`, make `krkr_patch.dll` for changing locale and redirect CHSPATCH  
* `krkr_sjis2utf16bom` , batch convert `sjis` files to `utf-16le-bom` format  

> つばさの丘の姫王

* `sdhime_xp3enc.cpp`,  make encrypted xp3 files  
* `sdhime_krkrpatch`, chs localization support

### artemis

* `artemis_pf8.py`,  pf8 format archive pack and unpack  

### tyrano

* `tyrano_extractexe.c` extract tyrano build-in exe files  

> Q-bit_キグルミキノコ (android)  

* `qbit_text.py` export and import text for translation

## (2) PC galgame

### azsystem

> ラムネ

* `lamune_hook.js`, decrypt the `*.asb` and `*.tbl` files  
* `lamune_patch.c`, semi-dynamic framework for chs localization
* `lamune_asbtext.py`, export or import text to `*.asb` files

### majiro

* `majiro_arc.py`, export and build majiro `*.arc` file
* `majiro_mjo.py`,  decrypt `*.mjo` file,  `MajiroObjX1.000` to `MajiroObjV1.000`
* `majiro_mjiltext.py`, export and import text from `*.mjil` file by `mjotool2`

> Winter Polaris

* `winterpolaris_hook.js`, dump `mjo` and analyze `majiro` in `winter polaris` game  
* `winterpolaris_patch.c`, Majirov3 dynamic hook framework code example  

> そらいろ // 230815 added
> ルリのかさね ～いもうと物語り // 230822 added

### systemnnn

* `systemnnn_patch.c`, patch sjis check, change font, redirect files, repalce `dwq` with png
* `systemnnn_spt.py`, parser `spt` opcode, export and import text

> 倭人異聞録～あさき、ゆめみし～

### yuris

> 越えざるは红い花 remaster

* `akaihana_yurispatch.c`, yuris gbk support  

> 3M_Marionettes

* `yuris_patch.c`, universe yuris patch, tested by 3M_Marionettes  

### advhd (willplus)

* `advhd_patch.c`, gbk support and overide arc file  
* `advhd_arcv1.py`, willplus advhd v1 arc pack or unpack  
* `advhd_arcv2.py`, willplus advhd v2 arc pack or unpack  
* `advhd_wsc.py`, willplus advhd v1 wsc text export or import  
* `advhd_ws2.py`, willplus advhd v2 ws2 text export or import  
* `advhd_pna.py`, willplus advhd pna export and import  

> あやかしごはん (advhd v1)  
> Blackish House (advhd v2)  
> 華は短し、踊れよ乙女 (advhd v2)  

### criware

> 祝姫

* `xtx_font.py`, `xtx` font decode and encode, for `祝姫`  
* `iwaihime_pc_decrypt.c`,  `sn.bin` decode  

### ig (innocent gray)

* `redirect_ig.c`, redirect the files to `xxx_chs` for separate CHSPATCH, tested in `天ノ少女`　`Innocent Gray`  

> 天ノ少女

### hibiki

> Natrual Vacation

* `hibiki_text_ks.py`, export and import game text for ftext format
* `hibiki_rename_picture.py`, rename all the picture name to crc32, to avoid sjis file name problem

### livemaker

> アイするキミの居場所

* `aikimi_loader.c`, a loader to dynamic inject DLL to the game
* `aikimi_patch.c`, patch the game dynamiclly to support `GBK` text

### bruns

> 解体挿入新書

* `bruns_decrypt.c` , decrypt  `EENZ` file,  `解体挿入新書` tested  

### ffa

> 天巫女姫

(comming soon ...)  

* `amanomiko_patch.c`, add new lzss support and gbk support
* `AmaNoMikoHime_lzss.py`, parse lzss compress file with header
* `AmaNoMikoHime_SO4.py`, export or import text in so4 files
* `AmaNoMikoHime_PT1.py`, parse PT1 image file rgb24 format

### exhibit

> 空色の風琴

* `sorairo_patch.c`, support for gbk enconding text in dll

### nvl  

> 我和她的世界末日  

* `nvl_asar.py`, to decrypt the `game.asar` made by nvlcloud  

## (3) Console galgame

### nippon1

> 夜廻3 (switch)

* `ykcmp.py`, an implementation in python to parse ykcmp compression.  
* `yomawari3_nltx.py`, deal with switch swizzle texture in nltx file.

> 神々の悪戯 (psp)

(comming soon ...)  

* `KamigamiNoAsobi_nispack.py`, export or import nispack  
* `KamigamiNoAsobi_story.py`, export or import text in story.dat  
* `KamigamiNoAsobi_font.py`, analyze the multi page font  
* `KamigamiNoAsobi_txp.py`, export or import txp picture  

### prototype

> Air (psv)

* `air_psv_dat.py`, dat picture（RGBA8888, RGB888, delta encoding,color panel） decode and encode  
* `air_psv_psbtext.py`, extract and import the text to PSV `air`, can be longer than origin  
* `air_psv_4bppfnt.py`, for building the psv air 4bpp font  

> Flowers (psv)

(comming soon ...)  

* `flowers_psv_text.py`, map flowers pc translation text  
* `flowers1-2_psv_pak.py`, `flowers3_psv_pak.py`, `flowers4_psv_pak.py` export or import *.pak  

> Island (psv)

* `island_psv_pak.py`, export or import *.pak

### eldia

> 神田アリスも推理スル (switch)

* `kanda_rs4.py`, parse rs4 file for importing text  
* `kanda_fontmap.c`, build the ConvertGb2312ToUtf16 arm64 binray code to support gb2312  
* `kanda_fontmap.py`, make the fontmap to gb2312 and patch sjis char check  

### hobibox

> Narcissus ナルキッソス～もしも明日があるなら (psp)

* `Narcissus_lzss.py`, parse lzss structure with header  
* `Narcissus_sn.py`, export or import sn.bin (after decompress)  
* `Narcissus_sntext.py`, export or import sn.bin (after extract) text  
* `Narcissus_2bppfont.py`, parse font.bin and make 2bpp font  
* `Narcissus_lbg.py`, extract and rebuild lbg texture  

### gss (takuyo)

> 月影の鎖 -錯乱パラノイア (psp, psv)

* `gss_arc.cs`, for `月影の鎖 -錯乱パラノイア` PSP, PSV see, my [pull request](https://github.com/morkt/GARbro/pull/435) in my forked GARBRO  

### cycrose

> 薔薇ノ木ニ薔薇ノ花咲ク (psp)

* `baranoki_psp_zp.py`, ``baranoki_psp_pk``, support `*.zp`, `*.pk` file for `薔薇ノ木ニ薔薇ノ花咲ク`  
* `baranoki_psp_vmc.py`, `baranoki_psp_pktext.py`, text support  
* `baranoki_psp_fontfnt.py`, `baranoki_psp_fontp.py`, tile font support  
* `baranoki_psp_boot.py`, rebuild the boot for fixing size buffer  

### if (idea factory)

> Jewelic Nightmare (psp)

(comming soon ...)  

* `Jewelic_UF.py`,  building the UF tile font,  for`Jewelic Nightmare (ジュエリック・ナイトメア)`  
* `Jewelic_STCM2L.py`,  converting the `ftext` (by [bintext.py](https://github.com/YuriSizuku/ReverseUtil/blob/master/script/bintext.py)) to STCM2Ltool format (made by [STCM2L_import.py](https://github.com/Yggdrasill-Moe/Helheim/blob/master/%E5%8D%81%E9%AC%BC%E4%B9%8B%E7%BB%8A/STCM2L_import.py)),  for`Jewelic Nightmare (ジュエリック・ナイトメア)`  

### konami

> ときめきメモリアル Girl's Side: 3rd Story (psp)

* `GS3_scriptEVSC.py`, parse EVSC opcode, export or import text  

### koei

> 金色のコルダ (psp)

(not finished ...)  

* `KiniroNoCorda_cdar.py`, parse cdvdar (type v2) structure  
* `KiniroNoCorda_eboot.py`, patch the eboot for chs support, extend the fontmap and font glphy memory  
* `KiniroNoCorda_eventdat.py`, parse event text, export and import  
* `KiniroNoCorda_font.py`, parse 4bpp 16X16 font  

> 遙かなる時空の中で (psp)

* `Harukanaru_cdar.py`, parse cdvdar (type v4) structure  
