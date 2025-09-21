"""
print or rebuild unity custom font
  v0.2, developed by devseed

tested games:
  神凪ノ杜 五月雨綴り, switch, 2021.3.31f1
  神凪ノ杜 五月雨綴り, psv, 5.6.6f2

thirdparty:
    UnityPy 1.22.5 (https://github.com/K0lb3/UnityPy/tree/bfea10a8d4f40296ef353b8464baf9a2a54574c5)
"""

import os
import copy
import numpy as np
import argparse
from PIL import Image

import UnityPy

__VERSION__ = "v0.2"

#region util
import math
import struct
import logging
from io import BytesIO
from dataclasses import dataclass
from typing import List, Union

import numpy as np
from PIL import Image, ImageDraw, ImageFont
@dataclass
class tbl_t:
    tcode : bytes = b""
    tchar : str = ""

@dataclass
class tile_t:
    w: int
    h: int
    bpp: int = 0
    size: int = 0

def save_tbl(tbl: List[tbl_t], outpath=None, *, encoding='utf-8')  -> List[str]:
    lines = []
    for t in tbl:
        raw_str = ""
        for d in t.tcode: raw_str += f"{d:02X}"
        line = ("{:s}={:s}\n".format(raw_str, t.tchar))
        lines.append(line)
    if outpath: 
        with open(outpath, "wt", encoding=encoding) as fp:
            fp.writelines(lines)
    return lines

def load_tbl(inpath: str, *, encoding='utf-8') ->  List[tbl_t]:
    """
    tbl file format "tcode=tchar", 
    :param inobj: can be path, or lines[], in the end, no \r \n
    :return: [(charcode, charstr)]
    """

    tbl: List[tbl_t] = []
    with open(inpath, "rt", encoding=encoding) as fp:
        lines = fp.readlines()

    for line in lines:
        if len(line) <= 0: continue
        indicator = line[0]
        if indicator == "#": continue
        if line.find("==") == -1: t1, tchar = line.split('=')
        else: t1 = line.split('=')[0]; tchar = '='
        tcode = bytearray(len(t1)//2)
        for i in range(len(t1)//2): tcode[i] = int(t1[2*i: 2*i+2], 16)
        tbl.append(tbl_t(bytes(tcode), tchar))

    return tbl

def make_cp932_tbl(range_full=True, text_fallback="♯", out_failed: List[int]=None) -> List[tbl_t]: 
    def _process(high, low):
        tcode = struct.pack('<BB', high, low)
        try:
            tchar = tcode.decode('sjis')
        except  UnicodeDecodeError:
            tchar = text_fallback          
            if out_failed!=None: out_failed.append(len(tbl))
        tbl.append(tbl_t(tcode, tchar))

    tbl = []
    for low in range(0x20, 0x7f): # asci
        tcode = struct.pack('<B', low)
        tbl.append(tbl_t(tcode, tcode.decode("sjis")))
    
    for high in range(0x81, 0xa0): # 0x81-0x9F
        for low in range(0x40, 0xfd):
            if low==0x7f: continue
            _process(high, low)
    
    # 0xE0-0xEF, sometimes 0xE0~-0xEA
    end = 0xf0 if range_full is True else 0xeb
    for high in range(0xe0, end): 
        for low in range(0x40, 0xfd):
            if low==0x7f: continue
            _process(high, low)

    logging.info(f"make tbl cp932 with {len(tbl)} chars")
    return tbl  

def make_cp936_tbl(range_kanji=False) -> List[tbl_t]:
    tbl: List[tbl_t] = []
    if range_kanji is False:
        for low in range(0x20, 0x7f): # asci
            tcode = struct.pack('<B', low)
            tbl.append(tbl_t(tcode, tcode.decode("gb2312")))
        
        for low in range(0xa1, 0xfe): # Punctuation
            tcode = struct.pack('<BB', 0xa1, low)
            tbl.append(tbl_t(tcode, tcode.decode("gb2312")))
        
        for low in range(0xa1, 0xfe): # fullwidth charactor
            tcode = struct.pack('<BB', 0xa3, low)
            tbl.append(tbl_t(tcode, tcode.decode("gb2312")))

        for low in range(0xa1, 0xf4): # hirakana
            tcode = struct.pack('<BB', 0xa4, low)
            tbl.append(tbl_t(tcode, tcode.decode("gb2312")))

        for low in range(0xa1, 0xf7): # katakana 
            tcode = struct.pack('<BB', 0xa5, low)
            tbl.append(tbl_t(tcode, tcode.decode("gb2312")))

    for high in range(0xb0, 0xf8): # Chinese charactor
        for low in range(0xa1, 0xff):
            if high == 0xd7 and 0xfa <= low <= 0xfe: continue
            tcode = struct.pack('<BB', high, low)
            tbl.append(tbl_t(tcode, tcode.decode("gb2312")))

    logging.info(f"make tbl cp936 with {len(tbl)} chars")
    return tbl

def make_image_font(tbl: List[tbl_t], ttfpath: str,
        tileinfo: tile_t, *, ntilerow=64, 
        render_overlap=3, render_size=0, render_shift=(0, 0)) -> np.ndarray:
    """
    :param tblobj: tbl object
    :param ttfobj: ttf font path or bytes
    :param tile: (w, h) 
    :param ntilerow: how many glphy in a row
    :param render_overlap: render multi times to increase brightness
    :param render_size: font size in each render glphy
    :param render_shift: (x, y) in each render glphy
    :return: img
    """

    n = len(tbl)
    w = ntilerow*tileinfo.w
    h = math.ceil(n/ntilerow)*tileinfo.h
    img = np.zeros((h, w, 4), dtype=np.uint8)
    logging.info(f"render font to image ({w}X{h}), {n} glphys {tileinfo.w}x{tileinfo.h}")
    
    if render_size==0: render_size=min(tileinfo.w, tileinfo.h)
    font = ImageFont.truetype(ttfpath, render_size)
    pil = Image.fromarray(img)
    pil.readonly = False # this to make share the memory
    draw = ImageDraw.Draw(pil)

    for i, t in enumerate(tbl):
        x = render_shift[0] + (i%ntilerow)*tileinfo.w
        y = render_shift[1] + (i//ntilerow)*tileinfo.h 
        draw.text((x,y), t.tchar, fill=(255,255,255,255), font=font, align="center")
    if render_overlap > 1: # alpha blending for overlap
        alpha = img[..., 3].astype(np.float32)/255.0
        for i in range(render_overlap-1): 
            alpha = alpha + (1-alpha)*alpha
        img[..., 3] = (alpha*255).astype(np.uint8)
    
    return img
#endregion

def find_unityobj(objs, name: str, selects=None):
    objid = int(name.replace("pathid", "")) if name.startswith("pathid") else None
    objname = name
    for obj in objs:
        # different types might has same id
        if selects is not None and  obj.type.name not in selects: continue
        try:
            data = obj.read()
            if objid is not None: 
                if objid == obj.path_id: 
                    return data
            else: 
                if data.m_Name == objname: 
                    return data
        except ValueError:
            pass
        except AttributeError:
            pass
    return None

def print_customfont(abpath, fontname, fontcfgname):
    env = UnityPy.load(abpath)
    font = find_unityobj(env.objects, fontname, "Texture2D")
    fontcfg = find_unityobj(env.objects, fontcfgname, "Font")
    w, h = font.m_Width, font.m_Height
    rect_sample = list(filter(lambda r: r.index == ord("亜"), fontcfg.m_CharacterRects))[0]
    for i, charinfo in enumerate(fontcfg.m_CharacterRects):
        tchar = chr(charinfo.index)
        pixelx, pixely = charinfo.uv.x * w, h - 11 - charinfo.uv.y * h
        glphyw, glphyh = charinfo.uv.width * w, charinfo.uv.height * h
        print(i, tchar, hex(charinfo.index), pixelx, pixely, glphyw, glphyh)

def rebuild_tbl(method="cjk", max_glphy=0, tblpath=None):
    if method == "tbl": return load_tbl(tblpath)
    tbl = None
    tbl_sjis = make_cp932_tbl(True)
    charset_sjis = set([ord(t.tchar) for t in tbl_sjis])
    tbl_gb2312 = make_cp936_tbl(True)
    charset_gb2312 = set([ord(t.tchar) for t in tbl_gb2312])
    if method == "cjk":
        charset_cjk = set([x for x in range(0x4e00, 0x9fa5)])
        charset_cjk |= charset_gb2312
        charset_cjk |= charset_sjis
        if len(charset_cjk) > max_glphy: # throw some of characters
            left = len(charset_cjk) - max_glphy
            charset_other = charset_cjk - charset_gb2312 - charset_sjis
            charset_other = set(list(charset_other)[:left])
            charset_cjk -= charset_other
        tbl = [tbl_t(x.to_bytes(2, "little", signed=False), chr(x)) for x in sorted(list(charset_cjk))]
    elif method == "gb2312sjis":
        charset_gb2312sjis = charset_sjis | charset_gb2312
        tbl = [tbl_t(x.to_bytes(2, "little", signed=False), chr(x)) for x in sorted(list(charset_gb2312sjis))]
    else: raise ValueError(f"[rebuild_tbl] invalid method {method}")
    return tbl

def rebuild_customefont(abpath, ttfpath, fontname, fontcfgname, 
        tbl, imgw, imgh, outpath=None, *,
        render_size=0, render_overlap=1, render_shift=(0, 0)):
    """
    imgw need to be 2**n for swizzle ? max 4096x4096 ? 
    """

    # load unity object
    env = UnityPy.load(abpath)
    font = find_unityobj(env.objects, fontname, "Texture2D")
    fontcfg = find_unityobj(env.objects, fontcfgname, "Font")
    
    # prepare cjk tbl
    glphyw = int(fontcfg.m_FontSize)
    nrow = imgw//glphyw
    rects = fontcfg.m_CharacterRects
    max_char = nrow * (imgh // glphyw)
    assert len(tbl) <= max_char, f"nglphy {len(tbl)} > {max_char}"

    # prepare font image
    if render_size == 0: render_size = glphyw
    fontimg = np.zeros([imgh, imgw, 4], dtype=np.uint8)
    tmpimg = make_image_font(tbl, ttfpath, 
                tile_t(glphyw, glphyw), ntilerow=nrow, 
                render_size=render_size, render_overlap=render_overlap, render_shift=render_shift)
    fontimg[:tmpimg.shape[0], :tmpimg.shape[1], :] = tmpimg
    fontimgpil = Image.fromarray(fontimg)
    print(f"rebuild fontimg {fontimg.shape[1]}x{fontimg.shape[0]} with {len(tbl)} chars")

    # make cjk fontmap
    rects_cjk = []
    rect_sample = list(filter(lambda r: r.index == ord("亜"), rects))[0]
    for i, t in enumerate(tbl):
        rect = copy.deepcopy(rect_sample)
        x, y = imgw + i%nrow * glphyw , (i // nrow) * glphyw
        rect.flipped = False
        rect.advance = float(glphyw)
        rect.index = ord(t.tchar)
        rect.uv.x = x / imgw
        rect.uv.y = (imgw - (glphyw - 1) - y) / imgw
        rect.uv.width = glphyw / imgw
        rect.uv.height =  glphyw / imgh
        rect.vert.x = 0
        rect.vert.y = glphyw
        rect.vert.width = glphyw
        rect.vert.height = -glphyw # this should be minus or it will be upside down
        if ord(t.tchar) < 0x80: # for half width char
            rect.advance /= 2
            rect.uv.width /= 2
            rect.vert.width /= 2
        rects_cjk.append(rect)

    # save font
    fontcfg.m_CharacterRects = rects_cjk
    fontcfg.save()
    font.image = fontimgpil
    font.save()
    if outpath is not None:
        outdir = os.path.dirname(outpath)
        with open(outpath, "wb") as fp:
            fp.write(env.file.save())
        fontimgpil.save(os.path.join(outdir, "customefont.png"))
        save_tbl(tbl, os.path.join(outdir, "customefont.tbl"))

def cli(cmdstr=None):
    parser = argparse.ArgumentParser(description=
            f"Unity custome font cli tools for rebuild"
            f"\n  {__VERSION__}, developed by devseed")

    parser.add_argument("method", choices=["print", "rebuild"], help="operation method")
    parser.add_argument("abpath", help="asssetbulde path or dir")
    parser.add_argument("fontname", type=str, help="name to find font, can use prefix pathidxxxx")
    parser.add_argument("fontcfgname", type=str, help="name to find fontcfg, can use prefix pathidxxxx")
    parser.add_argument("--ttfpath",type=str, default="default.ttf", help="select ttf to rebuild font")
    parser.add_argument("--rebuild-method",choices=["cjk", "gb2312sjis", "tbl"])
    parser.add_argument("--tblpath", type=str, help="for custome tbl rebuild method")
    parser.add_argument("--outpath", "-o", default="out", help="output path or dir")
    parser.add_argument("--glphyw", type=int, default=28, help="glphy width for esitimate max glphy count")
    parser.add_argument("--imgw", type=int, default=4096, help="texture width")
    parser.add_argument("--imgh", type=int, default=4096, help="texture height")
    parser.add_argument("--render-size", type=int, default=0, help="glphy render size")
    parser.add_argument("--render-overlap", type=int, default=0, help="glphy render size")
    parser.add_argument("--render-shiftx", type=int, default=0, help="glphy render pixel shift in x")
    parser.add_argument("--render-shifty", type=int, default=0, help="glphy render pixel shift in y")

    args = parser.parse_args(cmdstr.split(" ") if cmdstr else None)
    # for k, v in vars(args).items(): print(f"[cli] {k}={v}")
    abpath, fontname, fontcfgname = args.abpath, args.fontname, args.fontcfgname
    if args.method == "print":
        print_customfont(abpath, fontname, fontcfgname)
    elif args.method == "rebuild":
        ttfpath, outpath = args.ttfpath, args.outpath
        imgw, imgwh, glphyw = args.imgw, args.imgh, args.glphyw
        render_size, render_overlap = args.render_size, args.render_overlap
        render_sift = (args.render_shiftx, args.render_shifty)
        max_glphy = (imgw // glphyw) * (imgwh // glphyw)
        tbl = rebuild_tbl(args.rebuild_method, max_glphy, args.tblpath)
        rebuild_customefont(abpath, ttfpath, fontname, fontcfgname, 
            tbl, imgw, imgwh, outpath=outpath, render_size=render_size, 
            render_overlap=render_overlap, render_shift=render_sift)
    
if __name__ == "__main__":
    cli()

"""
history:
v0.1, custom font for 神凪ノ杜 五月雨綴り
v0.2, add cli for general purpose
"""