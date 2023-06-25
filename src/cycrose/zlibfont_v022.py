 # -*- coding: utf-8 -*-
import os
import math
import re
import struct
import copy
import codecs
import numpy as np
#import cv2
from PIL import ImageFont, ImageDraw, Image 

"""
libfont.py, by devseed
Utils for extracting, building tile font, or generating font picture, tbl

v0.1 initial version
v0.1.5 add function save_tbl, fix px48->pt error
v0.1.6 add gray2tilefont, tilefont2gray
v0.1.7 slightly change some function
v0.1.8 add generate_sjis_tbl, merge tbl, find_adding_char
v0.2 add extract_glphys from font image, 
     rebuild_tbl, merge two tbl with the same position of the same char
v0.2.1 align_tbl, manualy align tbl for glphys 
       by the adding offset(+-) at some position  
v0.2.2 replace_char, to replace useless char to new char in tbl
"""

def generate_gb2312_tbl(outpath=r"", only_kanji=False, replace_map={}):
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

    if len(replace_map) > 0:
        tbl = replace_char(tbl, replace_map)
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

def replace_char(tbl, replace_map): 
    """
    replace_char, to replace useless char to new char in tbl
    """
    tbl_replaced = []
    for t in tbl:
        charcode =t[0]
        c = t[1]
        if c in replace_map:
            c = replace_map[c]
        tbl_replaced.append((charcode, c))
    return tbl_replaced

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
    print("find_adding_char, " + str(len(index_adding)) + " adding chars!")
    return index_adding

def align_tbl(tbl, gap_map = dict(), 
        padding_item=(b'\xea\xa4', ''), outpath=""):
    """
    align_glphys_tbl, manualy align tbl for glphys 
        by the adding offset(+-) in gap_map at some position  
    """
    tbl_aligned = []
    skip = 0
    for i, t in enumerate(tbl):
        if skip > 0:
            skip -= 1
            continue

        if i in gap_map:
            n = gap_map[i]
            if  n < 0:
                skip = -n
                skip -= 1
                continue
            elif n > 0:
                tbl_aligned.append(t)
                for j in range(n): # dup place holder
                    tbl_aligned.append(padding_item) 
        else:
            tbl_aligned.append(t)
    
    if outpath!="": save_tbl(tbl_aligned, outpath)
    return tbl_aligned

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

def rebuild_tbl(tbl_base, tbl_new, outpath="", encoding="utf-8", *, 
        start_idx=-1, order=-1, index_reserved={}):
    """
    merge two tbl with the same position of the same char
    :params start_idx: the idx for rebuild replaced char start point
    :params order: the order for search replaced char, -1 end to start
    :params index_reserved: not cover this area after rebuild
    """
    def find_replaced_idx(start, end, step, index_reserved, index_same):
        for i in range(start, end, order):
            if (i not in index_reserved) and (i not in index_same):
                yield  i

    if len(tbl_new) > len(tbl_base):
        print("rebuild_tbl error! tbl_new(%d) is longer that tbl_base(%d)", len(tbl_new), len(tbl_base))
        return []

    index_same = []
    index_adding = find_adding_char(tbl_base, tbl_new, index_same)
    tbl_rebuild = copy.deepcopy(tbl_base)
    print("rebuild_tbl base_char=%d, adding_char=%d, same_char=%d" %
           (len(tbl_base), len(index_adding), len(index_same)))
   
    if start_idx < 0: 
        start_idx += len(tbl_base)
        end_idx = 0
    else:
        end_idx = len(tbl_base)
    gen_replaced_idx = find_replaced_idx(start_idx, end_idx, order, index_reserved, index_same)
    for i in range(len(index_adding)):
        c = tbl_new[index_adding[i]][1]
        idx = next(gen_replaced_idx)
        if idx is None:
            print("rebuild_tbl error! can not find replaced space!")
            return []
        charcode = tbl_base[idx][0]
        tbl_rebuild[idx] = (charcode, c)
    
    if outpath!="": save_tbl(tbl_rebuild, outpath, encoding=encoding)
    return tbl_rebuild

def load_tbl(inpath, encoding='utf-8'):
    """
    tbl struct: [charcode, char]
    tbl file: charcode=char, such as 8081=亜
    """
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
    print(inpath + " with " + str(len(tbl)) +" items loaded!")
    return tbl

def save_tbl(tbl, outpath="out.tbl", encoding='utf-8'):
    with codecs.open(outpath, "w", encoding='utf-8') as fp:
        for charcode, c in tbl:
            charcode_str = ""
            for d in charcode:
                charcode_str += f"{d:02X}"
            fp.writelines("{:s}={:s}\n".format(charcode_str, c))
        print("tbl with " + str(len(tbl)) + " items saved to " + outpath)

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

def extract_glphy(img, glphyw, glphyh, idx, 
                 f_idx2coord=None, f_orc=None):
    """
    extract glphy in a image by idx
    :params f_orc: (img, glphy, idx, x, y) -> c, use some ocr methed to detect the content of glphy
            such as pyorc, image_to_string(image)
    :return: glphy, x, y, c
    """
    def f_idx2coord_default(idx):
        line_idx = idx // line_count
        line_offset = idx % line_count
        x = line_idx * glphyh
        y = line_offset * glphyw  
        return x, y

    if f_idx2coord is None: f_idx2coord = f_idx2coord_default

    font = img
    fontw = font.shape[0]
    line_count = fontw//glphyw
    x, y = f_idx2coord(idx)
    glphy = Image.fromarray(font[y:y+glphyh, x:x+glphyw, :])
    c = f_orc(img, glphy, idx, x, y) if f_orc else ''
    try:
        print("glphy %d, at (%d, %d) %s"%(idx, x, y, c))
    except UnicodeDecodeError as e:
        print("glphy %d, at (%d, %d) %s"%(idx, x, y, ''))
    return glphy, x, y, c

def extract_glphys(imgpath, glphyw, glphyh, outdir="", 
        shifts=(0,0,0,0),  idxs = [], 
        tbl=None, f_idx2coord=None, f_orc=None):
    """
    extract glyphys form a font picture, 
    :params shifts: (left, right, top, bottom) to crop the image
    :params idxs: extract the glphy in these idxs
    :f_idx2coord: function to convert  glphy idx to coordinate
    :tbl: use tbl for name glphys, will ignore f_orc
    :f_orc: (img, glphy, idx, x, y) -> c
    :return font, coords, chars
    """

    if tbl is not None:  # using tbl for name glphy
        f_orc = lambda  img, glphy, idx, x, y: \
                tbl[idx][1] if idx<len(tbl) else ''
    font = np.array(Image.open(imgpath), np.uint8)
    font = font[shifts[0]:font.shape[0]-shifts[1], 
                shifts[2]:font.shape[1]-shifts[3], :]
    
    coords = []
    chars = []
    if idxs==[]:
        fontw, fonth = font.shape[0], font.shape[1]
        idxs = [x for x in range((fontw//glphyw)*(fonth//glphyh))]
    for i, idx in enumerate(idxs):
        glphy, x, y, c = extract_glphy(font, glphyw, glphyh, idx, f_idx2coord, f_orc)
        coords.append((x,y))
        chars.append(c)
        if outdir!="":
            if c=='':
                filename = f"{idx:04d}_{x:04d}_{y:04d}.png"
            else:
                filename = f"{idx:04d}_{x:04d}_{y:04d}_{c:s}.png"
            try:
                glphy.save(os.path.join(outdir, filename))
            except:
                filename = f"{idx:04d}_{x:04d}_u{ord(c[0]):04X}.png"
                glphy.save(os.path.join(outdir, filename))

    return font, coords, chars

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