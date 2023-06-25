"""
parsing font.bin for Narcissus psp, 
  v0.1, developed by devseed
  
  font.bin <-> font1.png, font2.png, fong3.png, font4.png
  fontx.tbl -> fontx.png -> font.bin
"""

import os
import sys
import mmap
import codecs
import struct
import numpy as np
from PIL import Image, ImageEnhance
from typing import Dict, Tuple

sys.path.append(os.path.join(
    os.path.dirname(__file__), 
    r"./../../util/script"))
try:
    import zlibfont_v024 as libfont
except:
    import libfont

# 2bpp, functions
def load_tbls(tblpath):
    tbls = []
    for i in range(4):
        tbl = libfont.load_tbl(os.path.splitext(tblpath)[0] + \
                str(i+1) + os.path.splitext(tblpath)[1])
        tbls.append(tbl)
    return tbls

def make_gb2312tbl(outpath=r"", only_kanji=False, replace_map=None):
    tbl = []
    if only_kanji is False:
        for low in range(0xa1, 0xfe): # Punctuation
            charcode = struct.pack('<BB', 0xa1, low)
            tbl.append((charcode, charcode.decode('gb2312')))

        for low in range(0xa1, 0xfe): # fullwidth charactor
            charcode = struct.pack('<BB', 0xa3, low)
            tbl.append((charcode, charcode.decode('gb2312')))

        for low in range(0xa1, 0xf4): # hirakana
            charcode = struct.pack('<BB', 0xa4, low)
            tbl.append((charcode, charcode.decode('gb2312')))

        for low in range(0xa1, 0xf7): # katakana 
            charcode = struct.pack('<BB', 0xa5, low)
            tbl.append((charcode, charcode.decode('gb2312')))

    for high in range(0xb0, 0xf8): # Chinese charactor
        for low in range(0xa1, 0xff):
            if high == 0xd7 and 0xfa <= low <= 0xfe: continue
            charcode = struct.pack('<BB', high, low)
            tbl.append((charcode, charcode.decode('gb2312')))

    if len(replace_map) > 0:
        tbl = libfont.replace_tblchar(tbl, replace_map)
    print("cp936 tbl with "+str(len(tbl))+" generated!")
    return tbl

def adjust_tbl(tblpath, outpath="font_sjis.tbl"):
    n = 0
    tbls = []
    for i in range(4):
        inpath = os.path.splitext(tblpath)[0] + \
                str(i+1) + os.path.splitext(tblpath)[1]
        with codecs.open(inpath, "r", "utf-8") as fp:
            lines = fp.readlines()

        tbl = []
        for line in lines:
            line = line.rstrip('\n').rstrip('\r')
            c = line.split('=')[-1]
            if len(c) != 1:
                tbl.append((b'\xff', '□'))
            elif c=='点' or c=='空':
                tbl.append((b'\xff', '□'))
            else:
                try:
                    tbl.append((c.encode('sjis'), c))
                    n += 1
                except UnicodeEncodeError as e:
                    tbl.append((b'\xff', '□'))
        tbls.append(tbl)
        if outpath!="":
            libfont.dump_tbl(tbl, os.path.splitext(outpath)[0] + \
                    str(i+1) + os.path.splitext(outpath)[1])
    print(n, "valid chars in", tblpath)
    return tbls

def merge_tbls(tbls):
    """
    merage 2bpp tbl pages to 1 tbl
    """

    tblfull = []
    charmap: Dict[int, Tuple(int, int)] = dict()
    for i, tbl in enumerate(tbls):
        for j, (charcode, c) in enumerate(tbl):
            if charcode==b'\xff': continue
            charmap.update({len(tblfull): (i, j)})
            tblfull.append((charcode, c))
    return tblfull, charmap

def make_chstbl(tblpath, outpath="font_chs.tbl"):
    """
    make gb2312, sjis mapping tbl
    """
    tbls = load_tbls(tblpath)
    tblfull, charmap = merge_tbls(tbls)
    # 啰瞭埼黯♪髦稣蹒跤霾鬓魅円踵鱿鳗栃踹峠踉惣
    replace_map = { '鲥':'「', 
                '鲦':'」',
                '礻':'？',
                '―': 'ー',
                '仝':'啰',
                '冖': '瞭',
                '廾':'埼',
                '彡':'黯',
                '钅':'♪',
                '蠲':'髦',
                '肀':'稣',
                '灬':'蹒',
                '爝':'跤',
                '毹':'霾',
                '毵':'鬓',
                '毹':'魅',
                '戬':'円',
                '戤':'踵',
                '戥':'鱿',
                '戢':'鳗',
                '尜':'栃',
                '尕':'踹',
                '漉':'峠',
                '嫠':'踉',
                '媸':'惣',
                '廴':'α'}
    tblgb2312 = make_gb2312tbl(only_kanji=False, replace_map=replace_map)

    index_reserved = []
    for i, (charcode, c) in enumerate(tblfull):
        d = int.from_bytes(charcode, 'little', signed=False)
        if d < 0x100:
            index_reserved.append(i)

    tblchs = libfont.rebuild_tbl(tblfull, 
        tblgb2312[:len(tblfull) - len(index_reserved)], 
        index_reserved=index_reserved)
    for k, v in charmap.items():
        tbls[v[0]][v[1]] = tblchs[k]

    if outpath!="":
        libfont.dump_tbl(tblchs, outpath)
        for i in range(4):
            tbl = libfont.dump_tbl(tbls[i], os.path.splitext(outpath)[0] + \
                str(i+1) + os.path.splitext(outpath)[1])
            tbls.append(tbl) 

    return tbls, tblchs

def extract_2bppfont(fontpath, outpath="out.png", 
    char_height=16, char_width=16, 
    colormap={0: 0, 1:128, 2:192, 3:255}):
    """
    font.bin -> font.png
    """
    
    with open(fontpath, 'rb') as fp:
        data = fp.read()

    datas = [bytearray(data) for i in range(4)]
    for i in range(len(data)):
        datas[0][i] = int(colormap[data[i]>>6])
        datas[1][i] = int(colormap[data[i]>>4 & 0x3])
        datas[2][i] = int(colormap[data[i]>>2 & 0x3])
        datas[3][i] = int(colormap[data[i] & 0x3])
    grays = [libfont.tilefont2gray(datas[i], \
        char_height, char_width, bpp=8) for i in range(4)]

    if outpath!="":
        for i, gray in enumerate(grays):
            imgpil = Image.fromarray(gray)
            imgpil.save(os.path.splitext(outpath)[0] + \
            str(i+1) + os.path.splitext(outpath)[1])

    return tuple(grays)

def make_2bppfont(tblpath, ttfpath, outpath="out.png", 
    char_height=16, char_width=16):
    """
    font.tbl -> font.png
    """

    tbls = load_tbls(tblpath)
    grays = []
    for tbl in tbls:
        bgra = libfont.build_picturefont(ttfpath, 
            tbl, char_width, char_height, pt=15)
        gray = np.zeros([bgra.shape[0], bgra.shape[1]], dtype=np.uint8)
        gray = bgra[:, :, 3]
        grays.append(gray)
    
    if outpath!="":
        for i, gray in enumerate(grays):
            imgpil = ImageEnhance.Brightness(
                Image.fromarray(gray)).enhance(1.4)
            imgpil.save(os.path.splitext(outpath)[0] + \
                str(i+1) + os.path.splitext(outpath)[1])
            grays[i] = np.array(imgpil)

    return grays

def compose_2bppfont(imgpath, tblpath, orgfontpath,
    outpath="out.bin", char_height=16, char_width=16, 
    n_chars=8192, colormap={0: 0, 1:128, 2:192, 3:255}):
    """
    font.png -> font.bin
    """

    def findincolormap(d):
        idx = 0
        for k, v in colormap.items():
            if abs(d - v) < abs(d - colormap[idx]):
                idx = k
        return idx

    # load gray image data
    grays = []
    for i in range(4):
        imgpil = Image.open(os.path.splitext(imgpath)[0] + \
                str(i+1) + os.path.splitext(imgpath)[1])
        grays.append(np.array(imgpil))
    datas = [bytearray(libfont.gray2tilefont(grays[i], \
        char_height, char_height, bpp=8, n_char=n_chars)) for i in range(4)]
    
    # fix the half-width char
    tbls = load_tbls(tblpath)
    fd = os.open(orgfontpath, os.O_RDWR)
    dataorg = mmap.mmap(fd, 0)
    datasorg = [bytearray(dataorg) for i in range(4)]
    for i in range(len(dataorg)):
        datasorg[0][i] = int(colormap[dataorg[i]>>6])
        datasorg[1][i] = int(colormap[dataorg[i]>>4 & 0x3])
        datasorg[2][i] = int(colormap[dataorg[i]>>2 & 0x3])
        datasorg[3][i] = int(colormap[dataorg[i] & 0x3])
    glphysize = char_height * char_width
    for i, tbl in enumerate(tbls):
        for j, (charcode, c) in enumerate(tbl):
            if (ord(c) >= 0x20 and ord(c) <0x80) or (c in {'♪'}):
                glphyrange = slice(j*glphysize, (j+1)*glphysize)
                datas[i][glphyrange] = datasorg[i][glphyrange]
    os.close(fd)
    
    # write the font.bin data
    data = bytearray(n_chars*char_height*char_width//4)
    for i in range(len(data)):
        d0 = findincolormap(datas[0][i]) if i < len(datas[0]) else 0
        d1 = findincolormap(datas[1][i]) if i < len(datas[1]) else 0
        d2 = findincolormap(datas[2][i]) if i < len(datas[2]) else 0
        d3 = findincolormap(datas[3][i]) if i < len(datas[3]) else 0
        data[i] = (d0<<6) + (d1<<4) + (d2<<2) + d3

    if outpath!="":
        with open(outpath, 'wb') as fp:
            fp.write(data)
    return data

def debug():
    pass

def main():
    if len(sys.argv) < 3:
        print("2bppfont e fontpath [outpath]")
        print("2bppfont c tblpath ttfpath orgfontpath [outdir]")
        return
    
    colormap = {0: 0, 1:255, 2:192, 3:128}
    
    if sys.argv[1].lower() == 'e':
        outpath = sys.argv[3] if len(sys.argv) > 3 else "out.png"
        extract_2bppfont(sys.argv[2], outpath, 
            char_height=16, char_width=16, 
            colormap=colormap)
    elif sys.argv[1].lower() == 'c':
        outdir = sys.argv[5] if len(sys.argv) > 5 else "./out"
        chstblpath = os.path.join(outdir, "font_chs.tbl")
        fontimgpath = os.path.join(outdir, "font_rebuild.png")
        outpath = os.path.join(outdir, "font_rebuild.bin")
        orgfontpath = sys.argv[4]
        make_chstbl(sys.argv[2], chstblpath)
        make_2bppfont(chstblpath, sys.argv[3], 
            fontimgpath, char_height=16, char_width=16)
        compose_2bppfont(fontimgpath, 
            chstblpath, orgfontpath, outpath,
            char_height=16, char_width=16, 
            n_chars=8192, colormap=colormap)
    else: raise ValueError(f"unknow format {sys.argv[1]}")

if __name__ == '__main__':
    # debug()
    main()
    pass