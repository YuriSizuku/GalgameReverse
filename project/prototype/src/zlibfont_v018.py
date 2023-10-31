 # -*- coding: utf-8 -*-
import os
import math
import re
import struct
import codecs
import numpy as np
from PIL import ImageFont, ImageDraw, Image 
"""
Utils for extracting, building tile font, or generating font picture.
And something about tbl.

v0.1 initial version
v0.1.5 add function save_tbl, fix px48->pt error
v0.1.6 add gray2tilefont, tilefont2gray
v0.1.7 slightly change some function
v0.1.8 add generate_sjis_tbl, merge tbl, find_adding_char
"""

def generate_gb2312_tbl(outpath=r"", only_kanji=False):
    tbl = []
    if only_kanji is False:
        for low in range(0x20, 0x7f): # asci
            charcode = struct.pack('<B', low)
            tbl.append((charcode, charcode.decode('gb2312')))
        
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

    if outpath!="": save_tbl(tbl, outpath)
    print("gb2312 tbl with " + str(len(tbl)) + " generated!")
    return tbl

def generate_sjis_tbl(outpath=r"", index_empty=None, fullsjis=True):
    tbl = []
    for low in range(0x20, 0x7f): # asci
        charcode = struct.pack('<B', low)
        tbl.append((charcode, charcode.decode('sjis')))
    
    for high in range(0x81, 0xa0): # 0x81-0x9F
        for low in range(0x40, 0xfd):
            if low==0x7f: continue
            charcode = struct.pack('<BB', high, low)
            try:
                c = charcode.decode('sjis')
            except  UnicodeDecodeError:
                c = '・'           
                if index_empty!=None:
                    index_empty.append(len(tbl))
            tbl.append((charcode, c))
    
    if fullsjis is True: end = 0xf0
    else: end =  0xeb
    for high in range(0xe0, end): # 0xE0-0xEF, sometimes 0xE0~-0xEA
        for low in range(0x40, 0xfd):
            if low==0x7f: continue
            charcode = struct.pack('<BB', high, low)
            try:
                c = charcode.decode('sjis')
            except  UnicodeDecodeError:
                c = '・'           
                if index_empty!=None:
                    index_empty.append(len(tbl))
            tbl.append((charcode, c))

    if outpath!="": save_tbl(tbl, outpath)
    print("sjis tbl with " + str(len(tbl)) + " generated!")
    return tbl

def find_adding_char(tbl_base, tbl_adding, index_same=None):
    """
    :param index_same: list, the index of the same char
    :return: list the index of the adding char
    """
    tbl_base_map = dict()
    adding_char = set()
    index_adding = []
    for i, t in enumerate(tbl_base):
        tbl_base_map.update({t[1]: i})
    for i, t in enumerate(tbl_adding): 
        if (t[1] not in tbl_base_map) and (t[1] not in adding_char):
            adding_char.add(t[1])
            index_adding.append(i)
            continue
        if index_same!=None and t[1] in tbl_base_map:
            index_same.append(tbl_base_map[t[1]])
            continue
    print(str(len(index_adding)) + " adding chars!")
    return index_adding

def merge_tbl(tbl1, tbl2, outpath=r""):
    """
    merge the charcode in tbl1 and the char in tbl2
    the return length is tbl1's
    """
    tbl = []
    for i in range(len(tbl1)):
        if i<len(tbl2): c= tbl2[i][1]
        else: c='・'
        tbl.append((tbl1[i][0], c))
    if outpath!="": save_tbl(tbl, outpath)
    print("tbl1 " + str(len(tbl1)) + ",  tbl2 "+ str(len(tbl2)) + " merged!")
    return tbl

def load_tbl(inpath, encoding='utf-8'):
    tbl = []
    with codecs.open(inpath, 'r', encoding=encoding) as fp:
        re_line = re.compile(r'([0-9|A-F|a-f]*)=(\S|\s)$')
        while True:
            line = fp.readline()
            if not line : break
            m = re_line.match(line)
            if m is not None:
                d = int(m.group(1), 16)
                if d<0xff:
                    charcode = struct.pack("<B", d)
                elif d>0xff and d<0xffff:
                    charcode = struct.pack(">H", d)
                else:
                    charcode = struct.pack(">BBB", d>>16, (d>>8)&0xff, d&0xff)
                #print(m.group(1), m.group(2), d)
                c = m.group(2)
                tbl.append((charcode, c))
    print(inpath + " with " + str(len(tbl)) +" loaded!")
    return tbl

def save_tbl(tbl, outpath="out.tbl", encoding='utf-8'):
    with codecs.open(outpath, "w", encoding='utf-8') as fp:
        for charcode, c in tbl:
            if len(charcode) == 1:
                d = struct.unpack('<B', charcode)[0]
            elif len(charcode) == 2:
                d = struct.unpack('>H', charcode)[0]
            fp.writelines("{:X}={:s}\n".format(d, c))
        print("tbl with " + str(len(tbl)) + " saved!")

def tilefont2bgra(data, char_height, char_width, bpp, n_row=64, n_char=0, f_decode=None):
    def f_decode_default(data, bpp, idx):
        b=g=r=a = 0
        start = int(idx)
        if bpp==4:
            a = 255
            d = struct.unpack('<B', data[start:start+1])[0]
            if idx > start:  d >>= 4
            else: d &= 0b00001111
            r = g = b = round(d*255/15)
        elif bpp==8:
            a = 255
            r = b = g = struct.unpack('<B', data[start:start+1])[0]
        else:
            print("Invalid bpp value!")
            return None
        return np.array([b, g, r, a], dtype='uint8')

    n =  math.floor(len(data)*8/bpp/char_height/char_width)
    if n_char!=0 and n_char < n: n = n_char
    width = char_width * n_row
    height = char_height * math.ceil(n/n_row)
    bgra = np.zeros([height, width, 4], dtype='uint8')
    if f_decode is None: f_decode = f_decode_default
    print("%dX%d %dbpp %d tile chars -> %dX%d image"
          %(char_width, char_height, bpp, n, width, height))

    for i in range(n):
        for y in range(char_height):
            for x in range(char_width):
                idx_y = (i//n_row)*char_height + y
                idx_x = (i%n_row)*char_width + x
                idx = (i*char_height*char_width + y * char_height + x)*bpp/8
                bgra[idx_y][idx_x]=f_decode(data, bpp, idx)

    return bgra

def bgra2tilefont(bgra, char_height, char_width, bpp, n_row=64, n_char=0, f_encode=  None):
    def f_encode_default(data, bgra, bpp, idx, idx_x, idx_y):
        if bgra.shape[2] == 4:
            b, g , r, _ = bgra[idx_y][idx_x].tolist()
        else: 
            b, g, r = bgra[idx_y][idx_x].tolist()
            # a = 255

        start = int(idx)
        if bpp==4:
            d = round((r+b+g)/3*15/255)
            if idx <= start:
                data[start] = (data[start] & 0b00001111) + (d<<4)
            else:
                data[start] = (data[start] & 0b11110000) + d
        elif bpp==8:
            struct.pack('<B', data[start:start+1], round((r+b+g)/3))
        else:
            print("Invalid bpp value!")
            return None

    height, width, _ = bgra.shape
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
                f_encode(data, bgra, bpp, idx, idx_x, idx_y)

    return data

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

def extract_tilefont(inpath, char_height, char_width, bpp, outpath=r".\out.png", n_row=64, n_char=0, addr=0, f_decode=None):
    with open(inpath, 'rb') as fp:
        fp.seek(addr)
        data = fp.read()
        bgra = tilefont2bgra(data, char_height, char_width, bpp, n_row=n_row, n_char=n_char, f_decode=f_decode)
        # cv2.imwrite(outpath, bgra)
        Image.fromarray(bgra[:, :, [2,1,0,3]]).save(outpath)
        print(outpath + " extracted!")

def build_tilefont(inpath, char_height, char_width, bpp, outpath=r".\out.bin", n_row=64, n_char=0, f_encode=None):
    # bgra = cv2.imread(inpath, cv2.IMREAD_UNCHANGED)
    img = Image.open(inpath)
    bgra = np.array(img, np.uint8)[:,:[2,1,0,3]]
    data = bgra2tilefont(bgra, char_height, char_width, bpp, n_row=n_row, n_char=n_char, f_encode=f_encode)
    with open(outpath, 'wb') as fp:
        fp.write(data)
    print(outpath + " tile font built!")

def build_picturefont(ttfpath, tblpath, char_width, char_height, n_row=64, 
        outpath="", *, padding=(0,0,0,0), pt=0, shift_x=0, shift_y=0):
    """
    :param tblpath: tblpath or tbl list
    :param padding: (up, down, left, right)
    """
    if type(tblpath) != str: tbl = tblpath
    else: tbl = load_tbl(tblpath)
    n = len(tbl)
    width = n_row*char_width + padding[2] + padding[3]
    height = math.ceil(n/n_row)*char_height + padding[0] + padding[1]
    img = np.zeros((height, width, 4), dtype=np.uint8)
    print("to build picture %dX%d with %d charactors..."%(width, height, n))
    
    ptpxmap = {8:6, 9:7, 16:12, 18:13.5, 24:18, 32:24, 48:36}
    if pt==0: pt=ptpxmap[char_height]
    font = ImageFont.truetype(ttfpath, pt)
    imgpil = Image.fromarray(img)
    draw = ImageDraw.Draw(imgpil)

    for i in range(n):
        c = tbl[i][1]
        x = (i%n_row)*char_width + padding[2] + shift_x
        y = (i//n_row)*char_height + padding[0] + shift_y
        draw.text([x,y], c, fill=(255,255,255,255), font=font)

    if outpath!="": imgpil.save(outpath)
    return np.array(imgpil)