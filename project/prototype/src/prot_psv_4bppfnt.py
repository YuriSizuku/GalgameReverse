 # -*- coding: utf-8 -*-
"""
    prototype v1 (with pak, tbl files) font build tool for psv
    v0.1, developed by devseed

    see also: 
    https://github.com/RikuKH3/prot_tblpak

    tested games:
    psv Air PCSG00940
    psv Clannad PCSG00415
    psv ヴァルプルガの詩 PCSG00768
"""

import struct
import math
import os
import sys
import numpy as np
import codecs
from PIL import ImageFont, ImageDraw, Image 

thisdir = os.path.dirname(sys.argv[0])
sys.path.append(os.path.join(thisdir, r"compat"))
import libfont_v180 as futil

def make_tblgb2312_inner(outpath=r""):
    tbl = []
    for low in range(0x20, 0x7f): # asci
        charcode = struct.pack('<B', low)
        tbl.append((charcode, charcode.decode('gb2312')))

    for low in range(0xa1, 0xc4): # part of Punctuation
        charcode = struct.pack('<BB', 0xa1, low)
        tbl.append((charcode, charcode.decode('gb2312')))
    
    for low in range(0xa1, 0xdb): # part of fullwidth chractor
        charcode = struct.pack('<BB', 0xa3, low)
        tbl.append((charcode, charcode.decode('gb2312')))

    for low in range(0xa1, 0xf4): # hirakana
        charcode = struct.pack('<BB', 0xa4, low)
        tbl.append((charcode, charcode.decode('gb2312')))

    for low in range(0xa1, 0xf5): # katakana 
        charcode = struct.pack('<BB', 0xa5, low)
        tbl.append((charcode, charcode.decode('gb2312')))

    for high in range(0xb0, 0xf8): # Chinese charactor
        for low in range(0xa1, 0xff):
            if high == 0xd7 and 0xfa <= low <= 0xfe: continue
            charcode = struct.pack('<BB', high, low)
            tbl.append((charcode, charcode.decode('gb2312')))

    # change sequence, 95-158,  271-334
    tmp = tbl[271:334]
    tbl[271:334] = tbl[95:158]
    tbl[95:158] = tmp

    # change 8179ぜ 817Aそ ->  81F4【 81F5】, fix name error
    tmp = tbl[300:302]
    tbl[300:302] = tbl[215:217]
    tbl[215:217] = tmp

    # change charactor, 凪
    for i in range(len(tbl)):
        if tbl[i][1] == '齄':
            tbl[i] = (tbl[i][0], '凪')

    # exchange sequence
    arr_char1 = ['啊', '阿', '埃', '挨', '哎', '唉', '哀', '皑', '癌', '蔼', '矮']
    arr_char2 = ['冫', '讠', '廴', '钅', '衤', '彳', '犭', '饣', '忄', '氵', '亻']
    arr_seq1 = len(arr_char1) * [0]
    arr_seq2 = len(arr_char2) * [0]

    for i in range(len(tbl)):
        for j in range(len(arr_char1)):
            if tbl[i][1] == arr_char1[j]:
                arr_seq1[j] = i
                break
        for j in range(len(arr_char2)):
            if tbl[i][1] == arr_char2[j]:
                arr_seq2[j] = i
                break
    for i in range(len(arr_seq1)):
        if i > len(arr_seq2): break
        tmp = tbl[arr_seq1[i]]
        tbl[arr_seq1[i]] = tbl[arr_seq2[i]]
        tbl[arr_seq2[i]] = tmp

    if outpath!="":
        with codecs.open(outpath, "w", encoding='utf-8') as fp:
            for charcode, c in tbl:
                if len(charcode) == 1:
                    d = struct.unpack('<B', charcode)[0]
                elif len(charcode) == 2:
                    d = struct.unpack('>H', charcode)[0]
                fp.writelines("{:X}={:s}\n".format(d, c))
    print("gb2312 with " + str(len(tbl)) + " generated!")
    return tbl

def make_picturefont(ttfpath, tbl, char_width, char_height, n_row, outpath="", padding=(0,0,0,0)):
    """
    :param padding: (up, down, left, right)
    """
    n = 2*len(tbl)
    width = n_row*char_width + padding[2] + padding[3]
    height = math.ceil(n/n_row)*char_height + padding[0] + padding[1]
    img = np.zeros((height, width, 4), dtype=np.uint8)
    print("to build picture %dX%d with %d charactors..."%(width, height, n))
    
    ptpxmap = {8:6, 9:7, 16:12, 18:13.5, 24:18, 32:24, 36:27}
    font = ImageFont.truetype(ttfpath, 28)
    imgpil = Image.fromarray(img)
    draw = ImageDraw.Draw(imgpil)

    for i in range(n):
        if i<n/2:
           c = tbl[i][1]
        else:
           c = tbl[i-n//2][1]
        x = (i%n_row)*char_width + padding[2]
        y = (i//n_row)*char_height + padding[0]
        draw.text([x,y], c, fill=(255,255,255,255), font=font)

    if outpath!="": imgpil.save(outpath)
    return np.array(imgpil)

def make_fontgb2312(fntpath, ttfpath, outpath):
    def f_encode(data, bgra, bpp, idx, idx_x, idx_y):
        b, g , r, a = bgra[idx_y][idx_x].tolist()
        start = int(idx)
        d = round(a*15/255)
        if idx > start:
            data[start] = (data[start] & 0b11110000) + d
        else:
            data[start] = (data[start] & 0b00001111) + (d<<4)

    tbl = make_tblgb2312_inner()
    tbl.append(('「'.encode('gb2312'), '「'))
    tbl.append(('」'.encode('gb2312'), '」'))
   
    n = len(tbl)
    with open(outpath, 'wb') as fp:
        with open(fntpath, 'rb') as fp2:
            fp.write(fp2.read(0x37B0))
        
        rbga = make_picturefont(ttfpath, tbl, 32, 32, 64, outpath=ttfpath+".png")
        data = futil.bgra2tilefont(rbga, 32, 32, 4, n_char=2*n, f_encode=f_encode)
        with open(outpath+".bin", 'wb') as fp2:
            fp2.write(data)
        futil.extract_tilefont(outpath+".bin", 32, 32, 4, outpath+".png")
        fp.write(data)

def make_tblgb2312(fntpath, outpath=""):
    tbl_gb2312 = make_tblgb2312_inner()
    tbl_gb2312.append(('「'.encode('gb2312'), '「'))
    tbl_gb2312.append(('」'.encode('gb2312'), '」'))
    tbl_sjis = []
    tbl = []
    with open(fntpath, 'rb') as fp:
        fp.seek(0x4)
        n = struct.unpack('<I', fp.read(4))[0]
        fp.seek(0x10)
        for i in range(n):
            buf = fp.read(2)
            if buf[1] == 0:
                buf=buf[0:1]
            else: 
                buf=buf[::-1]
            # print(buf)
            tbl_sjis.append((buf, " "))
    for i in range(len(tbl_gb2312)):
        tbl.append((tbl_sjis[i][0], tbl_gb2312[i][1]))

    if outpath!="":
        with codecs.open(outpath, "w", encoding='utf-8') as fp:
            for charcode, c in tbl:
                if len(charcode) == 1:
                    d = struct.unpack('<B', charcode)[0]
                elif len(charcode) == 2:
                    d = struct.unpack('>H', charcode)[0]
                fp.writelines("{:X}={:s}\n".format(d, c))
        print("tbl with " + str(len(tbl)) + " generated!")
    return tbl

def debug():
    def f_decode2(data, bpp, idx):
        b=g=r=a = 0
        start = int(idx)
        if bpp==4:
            d = struct.unpack('<B', data[start:start+1])[0]
            if idx <= start:  d >>= 4
            else: d &= 0b00001111
            a = r = g = b = round(d*255/15)
        return np.array([b, g, r, a], dtype='uint8')
    futil.extract_tilefont(r"D:\Make\Reverse\#pause\air_psv\test\mdnp32_dump.fnt", 32, 32, 4, r"D:\Make\Reverse\#pause\air_psv\test\mdnp32_dump.png", f_decode=f_decode2)
    pass

def main():
    if len(sys.argv) < 3:
        print("prot_psv_4bppfnt b936 fntpath ttfpath outpath")
        return
    
    if sys.argv[1].lower() == 'b936':
        fntpath = sys.argv[2]
        ttfpath = sys.argv[3]
        outpath = sys.argv[4]
        make_fontgb2312(fntpath, ttfpath, outpath)
        make_tblgb2312(fntpath, os.path.splitext(outpath)[0] + '.tbl')
    else: raise ValueError(f"option {sys.argv[1]} not supported")

if __name__ == "__main__":
    main()
    pass