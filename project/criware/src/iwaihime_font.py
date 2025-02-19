# -*- coding: utf-8 -*-

"""
make xtx format font for iwaihime (font48.xtx)
  v0.1, developed by devseed
"""

import os
import sys
import struct
import xtx_font

sys.path.append(os.path.join(os.path.dirname(__file__), r"compat"))
try:
    import compat.libfont_v180 as futil
except ImportError as e:
    pass

width = 6144
height = 3072
char_width = 48
char_height = 48
charcount = 8192

def generate_gb2312_tbl():
    pass

def generate_sjis_tbl():
    tbl = []
    for high in range(0x81, 0xa0): 
        for low in range(0x40, 0xfd):
            if low == 0x7f: continue
            charcode = struct.pack('<BB', high, low)
            try:
                c = charcode.decode('sjis')
            except UnicodeDecodeError:
                print(hex((high<<8)+low) + " unicode error!")
                c = '・'
            tbl.append((charcode, c))
    
    for high in range(0xe0, 0xed):
        for low in range(0x40, 0xfd):
            if low == 0x7f: continue
            charcode = struct.pack('<BB', high, low)
            try:
                c = charcode.decode('sjis')
            except UnicodeDecodeError:
                print(hex((high<<8)+low) + " unicode error!")
                c = '・'
            tbl.append((charcode, c))
    return tbl

def make_iwaihime_tbl(tblpath):
    tbl = []
    tbl_sjis = generate_sjis_tbl()
    tbl_gb2312 = futil.generate_gb2312_tbl()
    for i in range(charcount):
        if i<len(tbl_gb2312):
            tbl.append((tbl_sjis[i][0], tbl_gb2312[i][1]))
        else: 
            tbl.append(tbl_sjis[i])
    futil.save_tbl(tbl, tblpath)
    return tbl

def make_font_png():
    ttfpath =  r"C:\Windows\Fonts\simhei.ttf"
    tblpath = "asset/build/iwaihime_pc.tbl"
    pngpath = "asset/build/font48.png"
    xtxpath = "asset/build/font48.xtx"
    make_iwaihime_tbl(tblpath)
    n_row = width//char_width
    futil.build_picturefont(ttfpath, tblpath, char_width, char_height, n_row,  pngpath)
    xtx_font.xtx_font_build(pngpath, xtxpath)
    
if __name__=="__main__":
    make_font_png()