# -*- coding: UTF-8 -*-

"""
    for BaranoKiniBaranoSaku psp, 
    build fontp font
    v0.1, developed by devseed
"""

import os
from io import BytesIO
import struct
import codecs
import math
import numpy as np
from PIL import Image, ImageFont, ImageDraw

def generate_gb2312_tbl(outpath=r""):
    tbl = []
    for low in range(0x20, 0x7f): # asci
        charcode = struct.pack('<B', low)
        tbl.append((charcode, charcode.decode('gb2312')))
    
    for low in range(0xa1, 0xfe): # Punctuation
        charcode = struct.pack('<BB', 0xa1, low)
        tbl.append((charcode, charcode.decode('gb2312')))
    
    for low in range(0xa1, 0xfe): # fullwidth chractor
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

def tilefont2gray(data, char_height, char_width, bpp=8, n_row=64, n_char=0, f_decode=None):
    def f_decode_default(data, bpp, idx):
        start = int(idx)
        d = 0
        if bpp==8:
            d = struct.unpack('<B', data[start:start+1])[0]
        else:
            print("Invalid bpp value!")
            return None
        return d

    n =  math.floor(len(data)*8/bpp/char_height/char_width)
    if n_char!=0 and n_char < n: n = n_char
    width = char_width * n_row
    height = char_height * math.ceil(n/n_row)
    gray = np.zeros([height, width], dtype='uint8')
    if f_decode is None: f_decode = f_decode_default
    print("%dX%d %dbpp %d tile chars -> %dX%d image"
          %(char_width, char_height, bpp, n, width, height))

    for i in range(n):
        for y in range(char_height):
            for x in range(char_width):
                idx_y = (i//n_row)*char_height + y
                idx_x = (i%n_row)*char_width + x
                idx = (i*char_height*char_width + y * char_height + x)*bpp/8
                gray[idx_y][idx_x]=f_decode(data, bpp, idx)

    return gray

def gray2tilefont(gray, char_height, char_width, bpp=8, n_row=64, n_char=0, f_encode=  None):
    def f_encode_default(data, gray, bpp, idx, idx_x, idx_y):
        start = int(idx)
        if bpp==8:
            d = gray[idx_y][idx_x]
            struct.pack('<B', data[start:start+1], d)
        else:
            print("Invalid bpp value!")
            return None

    height, width, _ = gray.shape
    n = (height/char_height) * (width/char_width) 
    if n_char != 0 and n_char < n: n = n_char
    size = math.ceil(n*bpp/8*char_height*char_width) 
    data = bytearray(size)
    if f_encode is None: f_encode=f_encode_default
    print("%dX%d image -> %dX%d %dbpp %d tile chars, %d bytes"
          %(width, height, char_width, char_height, bpp, n, size))

    for i in range(n):
        for y in range(char_height):
            for x in range(char_width):
                idx_y = (i//n_row)*char_height + y
                idx_x = (i%n_row)*char_width + x
                idx =  (i*char_height*char_width + y * char_height + x)*bpp/8
                f_encode(data, gray, bpp, idx, idx_x, idx_y)

    return data

def extract_fontp(inpath, outdir, encoding='sjis'):
    fontname = os.path.split(inpath)[1].split('.')[0]
    glyphstrpath = os.path.join(outdir, fontname + ".txt")
    tilefontpath = os.path.join(outdir, fontname + ".tile")
    imgfontpath = os.path.join(outdir, fontname + ".png")

    tilefont = BytesIO()
    glyphbstrs = []
    grayfont = None
    char_width = 22
    char_height = 22

    with open(inpath, 'rb') as fp:
        n = int.from_bytes(fp.read(4), 'little')
        print(fontname + " with " + str(n) + " glphies to extract...")
        while True:
            glybstr = bytearray(fp.read(8))
            if not glybstr: break
            glyphbstrs.append(glybstr)
            fp.seek(120, 1) # in total 128 str len
            size1, size2 = struct.unpack('<II', fp.read(8)) # 620 484(22X22)
            #print(glybstr, size1, size2)
            tilefont.write(fp.read(size2))

    with codecs.open(glyphstrpath, 'wb', 'utf-8') as fp:
       for item in glyphbstrs:
            tmp = bytearray(item)
            for i in range(len(item)):
                if tmp[i]==0xff: tmp[i]=0
            fp.writelines(tmp.decode(encoding).strip('\0')+'\n')
    
    tilefont.seek(0)
    tilefontdata = tilefont.read()
    with open(tilefontpath, 'wb') as fp:
        fp.write(tilefontdata)
    grayfont = tilefont2gray(tilefontdata, char_height, char_width)
    im = Image.fromarray(grayfont)
    im.save(imgfontpath)
    return tilefontdata, glyphbstrs, grayfont

def make_fontp(tilefontdata, glyphbstrs, outpath):
    n = len(glyphbstrs)
    print(outpath + " with " + str(n) + " glphies to build...")
    with open(outpath, 'wb') as fp:
        fp.write(int.to_bytes(n, 4, 'little'))
        for i in range(n):
            buf = bytearray(b'\xff'*128)
            buf[0:len(glyphbstrs[i])] = glyphbstrs[i]
            fp.write(buf)
            fp.write(struct.pack("<II", 620, 484))
            fp.write(tilefontdata[484*i : 484*(i+1)])

def format_glybstr(num, c, encoding):
    glybstr = bytearray(b'\xff' * 8)
    numbstr = str(num).encode()
    cbstr = c.encode(encoding)
    if len(numbstr) < 4:
        glybstr[0:4-len(numbstr)] = b'\x20' * (4-len(numbstr))
    glybstr[4-len(numbstr):len(numbstr)] = numbstr
    glybstr[4] = 0x5f
    glybstr[5:5+len(cbstr)] = cbstr
    glybstr[5+len(cbstr)] = 0
    return bytes(glybstr)

def make_sjis_font(ttfpath, outpath):
    pass

def make_gb2312_font(ttfpath, outpath):
    tbl = generate_gb2312_tbl()
    tilefont = BytesIO()
    glyphbstrs = []
    char_width = 22
    char_height = 22
    font = ImageFont.truetype(ttfpath, 17)
    
    print("to make gb2312 tile font with " + str(len(tbl)) + " charactors...")
    for i, item in enumerate(tbl):
        c = item[1]
        glybstr = format_glybstr(i, c, 'gb2312')
        glyphbstrs.append(glybstr)
        img_patch = np.zeros([char_height, char_width], dtype='uint8')
        imgpil = Image.fromarray(img_patch, 'L')
        draw = ImageDraw.Draw(imgpil)
        draw.text([0,0], c, fill=255, font=font)
        tilefont.write(imgpil.tobytes())
    print("to make fontp ...")
    make_fontp(tilefont.getbuffer(), glyphbstrs, outpath)
        
def main():
    pass

def debug():
    make_gb2312_font(r".\build\intermediate\default.ttf", r".\build\intermediate\afs01\font.p")
    tilefontdata, glyphbstrs,  grayfont = extract_fontp(r".\build\intermediate\afs01\font.p",r".\build\intermediate", encoding='gb2312')
    #make_fontp(tilefontdata, glyphbstrs, r".\build\intermediate\font1_rebuild.p")

if __name__ == "__main__":
    debug()