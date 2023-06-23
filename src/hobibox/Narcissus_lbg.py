"""
to extract and rebuild lbg texture for Narcissus psp, 
  v0.1, developed by devseed
  
"""

import os
import sys
import mmap
import struct
import numpy as np
from io import SEEK_END
from PIL import Image

def pspswi_swizzle(x, y, w, blockw=16, blockh=8, bpp=32):
    rowblocks = w//blockw
    blockx = x//blockw
    blocky = y//blockh
    x2 = x - blockx*blockw
    y2 = y - blocky*blockh
    blockidx = blockx + blocky*rowblocks
    blockaddr = blockidx * blockw * blockh
    # return 4*(x + w*y)
    return (bpp//8)*(blockaddr + x2 + y2*blockw)

def gxtswi_swizzle(x, y, w, bpp=32):
    swimap = [
        0, 1, 8, 9, 
        2, 3, 10, 11,
        16, 17, 24, 25,
        18, 19, 26, 27,
            
        4, 5, 12, 13,
        6, 7, 14, 15,
        20, 21, 28, 29,
        22, 23, 30, 31,

        32, 33, 40, 41,
        34, 35, 42, 43,
        48, 49, 56, 57,
        50, 51, 58, 59,
            
        36, 37, 44, 45,
        38, 39, 46, 47,
        52, 53, 60, 61,
        54, 55, 62, 63
    ]
    t = (y*w + x) % len(swimap)
    x2 = x//8
    y2 = y//8
    return (bpp//8)*((swimap[t]//8+y2)*w + (swimap[t]%8)+x2)

def lbg_deswizzle(idx, w, h):
    """
    actualy, this is not really swizzle
    just tile twice
    """
    blockw1 = 4 # inner
    blockh1 = 8
    blockw2 = 16 # outer
    blockh2 = h//blockh1 # 34
    blocksize1 = blockh1 * blockw1
    blocksize2 = blocksize1 * blockh2 * blockw2

    blockidx2 = idx // blocksize2 # outer tile idx
    blockoffset2 = idx % blocksize2 
    blockidx1 = blockoffset2 // blocksize1 # inner tile idx
    blockoffset1 = blockoffset2 % blocksize1
     
    blockx1 = blockoffset1 % blockw1
    blocky1 = blockoffset1 // blockw1
    blockx2 = blockidx1 % blockw2
    blocky2 = blockidx1 // blockw2
    xbase = blockidx2 * blockw2 * blockw1
    ybase = 0
    x = xbase + blockx2 * blockw1 + blockx1
    y = ybase + blocky2 * blockh1 + blocky1
    return x, y

def export_lbg(lbgpath, outpath="./out.png"):
    fd = os.open(lbgpath, os.O_RDWR)
    data = mmap.mmap(fd, 0)
    
    hsize = 0x20
    fsize = len(data)
    w, h = struct.unpack("<HH", data[0x14:0x18])
    w = (fsize - hsize) // h // 4
    bgra = 255* np.ones([h, w, 4], dtype=np.uint8)

    for idx in range(w*h):
        x, y = lbg_deswizzle(idx, w, h)
        offset = idx * 4 + hsize
        bgra[y, x] = np.frombuffer(
            data[offset: offset+4], dtype=np.uint8)

    os.close(fd)

    if outpath!="":
        imgpil = Image.fromarray(bgra)
        imgpil.save(outpath)

    return bgra

def import_lbg(imgpath, orgpath, outpath="./out.lbg"):
    bgra = np.array(Image.open(imgpath))
    hsize = 0x20
    with open(orgpath, 'rb') as fp:
        dataheader = fp.read(hsize)
        fp.seek(0, SEEK_END)
        fsize = fp.tell()
        
    data = bytearray(fsize)
    data[0: hsize] = dataheader
    w, h = struct.unpack("<HH", data[0x14:0x18])
    w = (fsize - hsize) // h // 4

    for idx in range(w*h):
        x, y = lbg_deswizzle(idx, w, h)
        offset = idx * 4 + hsize
        data[offset: offset+4] = bgra[y, x].tobytes()

    if outpath!="":
        with open(outpath, 'wb') as fp:
            fp.write(data)

    return data

def fix_lbg(imgpath, outpath="./out.png", droprx = 16):
    """
    512 -> 480
    :params droprx: drop the pixels on the right
    """
    
    bgra = np.array(Image.open(imgpath))
    h, w, c = bgra.shape[0], bgra.shape[1], bgra.shape[2]

    blockw = 64
    dropx = 2
    n = w // blockw
    bgra_fix = np.zeros((h, w - n*dropx, c), dtype=np.uint8)
    for i in range(n):
        bgra_fix[:, i*(blockw-dropx): (i+1)*(blockw-dropx),:] \
            = bgra[:, i*blockw + 1: (i+1)*blockw - 1, :]
    if droprx > 0: bgra_fix = bgra_fix[:, :bgra_fix.shape[1]-droprx, :]

    if outpath:
        imgpil = Image.fromarray(bgra_fix)
        imgpil.save(outpath)

    return bgra_fix

def invfix_lbg(imgpath, outpath="./out.png", droprx = 16, orgw=512):
    """
    480 -> 512
    """

    bgra = np.array(Image.open(imgpath))
    h, w, c = bgra.shape[0], bgra.shape[1], bgra.shape[2]
    # if c < 4:
    #     a = np.ones((h, w), np.uint8) * 255
    #     bgra = np.dstack([bgra[:,:, 0], bgra[:, :, 1], bgra[:, :, 2], a])

    blockw = 64
    dropx = 2
    n = orgw // blockw
    bgra_invfix = np.zeros((h, orgw, c), dtype=np.uint8)

    for i in range(n-1):
        bgra_invfix[:, i*blockw + 1: (i+1)*blockw - 1, :] \
            = bgra[:, i*(blockw-dropx): (i+1)*(blockw-dropx),:]
        # fix gap
        bgra_invfix[:, i*blockw, :] = bgra[:, i*(blockw-dropx),:]
        bgra_invfix[:, (i+1)*blockw - 1, :] = bgra[:, (i+1)*(blockw-dropx),:]
        
    bgra_invfix[:, (n-1)*blockw + 1: n*blockw - 1 - droprx, :] \
            = bgra[:, (n-1)*(blockw-dropx):,:]
    bgra_invfix[:, (n-1)*blockw, :] = bgra[:, (n-1)*(blockw-dropx),:]
    
    # fix the right cap
    bgra_invfix[:, n*blockw - droprx-1: , :] = bgra[:, -1:,:]
    
    if outpath:
        imgpil = Image.fromarray(bgra_invfix)
        imgpil.save(outpath)

    return bgra_invfix

def debug():
    # export_lbg(r"D:\Make\Reverse\Narcissus_psp\test\lbg\3008.spc.dec")
    fix_lbg(r"D:\Make\Reverse\Narcissus_psp\test\lbg\bg_1005.spc.png")
    pass

def main():
    if len(sys.argv) < 3:
        print("Narcissus_lbg e inpath [outpath]")
        print("Narcissus_lbg i inpath orgpath [outpath]")
        print("Narcissus_lbg f inpath [outpath]")
        print("Narcissus_lbg invf inpath [outpath]")
        return
    
    if sys.argv[1].lower() == 'e':
        outpath = sys.argv[3] if len(sys.argv) > 3 else "out.png"
        export_lbg(sys.argv[2], outpath)
    elif sys.argv[1].lower() == 'i':
        outpath = sys.argv[4] if len(sys.argv) > 4 else "out.bin"
        import_lbg(sys.argv[2], sys.argv[3], outpath)
    elif sys.argv[1].lower() == 'f':
        outpath = sys.argv[3] if len(sys.argv) > 3 else "out.png"
        fix_lbg(sys.argv[2], outpath)
    elif sys.argv[1].lower() == 'invf':
        outpath = sys.argv[3] if len(sys.argv) > 3 else "out.png"
        invfix_lbg(sys.argv[2], outpath)
    else: raise ValueError(f"unknow format {sys.argv[1]}")

if __name__ == '__main__':
    # debug()
    main()
    pass