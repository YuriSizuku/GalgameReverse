# -*- coding: UTF-8 -*-
"""
    for BaranoKiniBaranoSaku psp, 
    build fnt font
    v0.1, developed by devseed
"""

import os
import sys
from io import BytesIO
import struct
import codecs

sys.path.append(os.path.join(os.path.dirname(sys.argv[0]), r"compat"))
import libfont_v220 as futil

def make_monospaced_fnt(tbl, ttfpath):
    def f_encode(data, bgra, bpp, idx, idx_x, idx_y):
        if bgra.shape[2] == 4:
            b, g , r, a = bgra[idx_y][idx_x].tolist()
        else: 
            b, g, r = bgra[idx_y][idx_x].tolist()
        d = round(a*15/255)
        start = int(idx)
        if idx <= start:
            data[start] = (data[start] & 0b00001111) + (d<<4)
        else:
            data[start] = (data[start] & 0b11110000) + d

    size_header = 0x24
    size_fontmap = 10 * len(tbl)
    data = BytesIO()
    fontmap = []

    print("to make monospaced fnt with " + str(len(tbl)) + " chars")
    for i in range(len(tbl)):
        offset = i*128 + size_header + size_fontmap
        wchar = tbl[i][0].decode('utf-16le')
        fontmap.append([wchar, 16, 16, 16, 0, 0, offset])
    for item in fontmap: # build fnt fontmap
        wchar, display_width, char_width, char_height, y, x, offset = item
        offset_l = offset & 0xff
        offset_h = offset >> 8
        data.write(struct.pack('<HBBBBBBH', ord(wchar), display_width, char_width, char_height, y, x, offset_l, offset_h))

    print(hex(data.tell()), hex(size_fontmap))
    char_height = 16
    char_width = 16
    bgra = futil.build_picturefont(ttfpath, tbl, 
                char_height, char_width, 
                pt=13, shift_x=2, shift_y=2)
    data_glyph = futil.bgra2tilefont(bgra, char_height, char_width, 4, n_char=len(tbl), f_encode=f_encode)
    data.write(data_glyph)

    return fontmap, data.getbuffer()

def extract_fnt(inpath, outdir=""): # as not monospaced glyph, no extract image now
    with open(inpath, 'rb') as fp:
        data_header = fp.read(0x24)
        bpp, width_max, n = struct.unpack('<BBH', data_header[:4])
        
        fontmap = []
        for i in range(n):
            c, display_width, char_width, char_height, y,  x, offset_l, offset_h = struct.unpack('<HBBBBBBH', fp.read(10))
            wchar = chr(c)
            offset = (offset_h<<8)+offset_l
            fontmap.append([wchar, display_width, char_width, char_height, y,  x, offset])
        data_glyph = fp.read()

    if outdir!="":
        fp = codecs.open(os.path.join(outdir, "fontmap.txt"), 'wb', encoding='utf-8')
        for i in range(len(fontmap)-1):
            offset_next = fontmap[i+1][-1]
            wchar,  display_width, char_width, char_height, y,  x, offset = fontmap[i]
            #print(wchar, hex(ord(wchar)), display_width, char_width, char_height, y,  x, hex(offset), offset_next - offset)
            linestr = str.format("({:s},{:s}) {:d} {:d} {:d} {:d} {:d} {:s} {:d}",wchar, hex(ord(wchar)),
            display_width, char_width, char_height, y,  x, 
            hex(offset), offset_next - offset )
            print(linestr)
            fp.write(linestr+"\n")
        fp.close()

    return fontmap, data_header, data_glyph

def build_fntgb2312(fntpath, ttfpath, outpath):
    # fontmap, [wchar, display_width, char_width, char_height, y,  x, offset]
    fontmap, data_header, _ = extract_fnt(fntpath)
    print("%d chars in fnt font"%(len(fontmap)))

    # build tbl
    replace_map = { '鲥':'「', 
                    '鲦':'」', 
                    '礻':'跤', 
                    '冖':'霭',
                    '鬯' : '跄',
                    '讠':'踉', 
                    '卩':'龌', 
                    '阝':'龊'}
    tbl_gb2312 = futil.generate_gb2312_tbl(replace_map=replace_map)
    tbl_game = []
    tbl_rebuild = []
    index_reserved = []
    for i, item in enumerate(fontmap):
        tbl_game.append([item[0].encode('utf-16le'), item[0]])
        try:
            tmp = item[0].encode('sjis')
            if len(tmp) < 2:
                print(i, hex(ord(item[0])), item[0], "not 2byte")
                index_reserved.append(i)
        except:
            print(i, item[0], "not sjis")
            index_reserved.append(i)
    
    print("%d chars not convert to sjis"%(len(index_reserved)))
    tbl_rebuild = futil.rebuild_tbl(tbl_game, 
            tbl_gb2312[:len(tbl_game)-len(index_reserved)], 
            outpath+'.tbl', index_reserved=index_reserved)
    
    # create fnt
    _, data_content = make_monospaced_fnt(tbl_rebuild, ttfpath)
    with open(outpath, 'wb') as fp:
        data_header = bytearray(data_header)
        #data_header[0x4:0x24] = 0x10 * [0xae, 0x2] 
        fp.write(bytes(data_header))
        fp.write(data_content)

    # convert UTF-16 to sjis
    for i, t in enumerate(tbl_rebuild):
        wchar = t[0].decode('utf-16le')
        try:
            charcode = wchar.encode('sjis')
        except:
            charcode = b'\xff\xff'
        tbl_rebuild[i] = (charcode, t[1])
    futil.save_tbl(tbl_rebuild, outpath+'.tbl')

def main():
    if len(sys.argv) < 3:
        print("baranoki_psp_fontfnt b936 fntpath ttfpath outpath")
        print("baranoki_psp_fontfnt e fntpath outpath")

    fntpath = sys.argv[2]
    if sys.argv[1].lower() == 'b936':
        ttfpath = sys.argv[3]
        outpath = sys.argv[4]
        build_fntgb2312(fntpath, ttfpath, outpath)
    elif sys.argv[1].lower() == 'e':
        outpath = sys.argv[3]
        extract_fnt(fntpath, outpath)
    else: raise ValueError(f"not recognized pattern {sys.argv[1]}")

def debug():
    pass

if __name__ == "__main__":
    main() 
    pass