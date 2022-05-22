"""
A tool for exporting and importing nltx texture, tested by yonamwari3
ntlx -> ykcmp -> nxswitexture
    developed by devseed, v0.1
"""

import sys
import struct
import numpy as np
from PIL import Image
import ykcmp

def nxswi_deswizzle(x, y, image_width, bytes_per_pixel, base_addr, block_height):
    """
    From the Tegra X1 TRM
    """
    def DIV_ROUND_UP(n, d):
        return (n + d - 1) // d

    image_width_in_gobs = DIV_ROUND_UP(image_width * bytes_per_pixel, 64)
    gob_addr = (base_addr
        + (y//(8*block_height))*512*block_height*image_width_in_gobs
        + (x*bytes_per_pixel//64)*512*block_height
        + (y%(8*block_height)//8)*512)
    x *= bytes_per_pixel
    addr = (gob_addr + ((x % 64) // 32) * 256 + ((y % 8) // 2) * 64
               + ((x % 32) // 16) * 32 + (y % 2) * 16 + (x % 16))
    return addr

def decode_nxswitexure(data, imgw=0, imgh=0, blockh=16, outpath=""):
    """
    decode switch R8_G8_B8_A8_UNORM texture with swizzle
    """
    if imgw==0: imgw = np.int(np.sqrt(len(data)/4))
    if imgh==0: imgh = np.int(np.sqrt(len(data)/4))
    bgra =np.zeros((imgh, imgw, 4), dtype=np.uint8)
    if blockh==0:
        if imgw<=64 or imgh<=64: blockh=8
        else: blockh=16
    for x in range(imgw):
        for y in range(imgh):
            idx = nxswi_deswizzle(x, y, imgw, 4, 0, blockh)
            b, g, r, a = struct.unpack('<BBBB', data[idx: idx+4])
            bgra[y, x, :] = np.array([b, g, r, a])
    if outpath!="":
        imgpil = Image.fromarray(bgra[...,[2,1,0,3]])
        imgpil.save(outpath)
    return bgra

def encode_nxswitexture(bgra, blockh=16, outpath=""):
    """
    encode switch R8_G8_B8_A8_UNORM texture with swizzle
    """
    data = bytearray(bgra.nbytes)
    imgw = bgra.shape[1]
    imgh = bgra.shape[0]
    if blockh==0:
        if imgw<=64 or imgh<=64: blockh=8
        else: blockh=16
    for x in range(imgw):
        for y in range(imgh):
            idx = nxswi_deswizzle(x, y, imgw, 4, 0, blockh)
            b, g, r, a = bgra[y, x, :]
            data[idx:idx+4] = struct.pack("<BBBB", b, g, r, a)
    if outpath!="":
        with open(outpath, 'wb') as fp:
            fp.write(data)
    return data

def extract_nltx(inpath, outpath=""):
    with open(inpath, 'rb') as fp:
        data = fp.read()
    w, h = struct.unpack('<II', data[0x18: 0x18+8])
    texdata = ykcmp.decompress_ykcmpv1(data[0x80:])
    return decode_nxswitexure(texdata, w, h, 0, outpath)

def insert_nltx(inpath, insertpath, outpath=""):
    with open(inpath, 'rb') as fp:
        data = fp.read(0x80)
    bgra =  np.array(Image.open(insertpath))[:,:,[2,1,0,3]]
    texdata = encode_nxswitexture(bgra, 0)
    ykcmpdata = ykcmp.compress_ykcmpv1(texdata)
    with open(outpath, 'wb') as fp:
        fp.write(data)
        fp.write(ykcmpdata)
        
def debug():
    pass

def main():
    if len(sys.argv) < 3:
        print("yomawari3_nltx e(extract) nltxpath [outpath]") 
        print("yomawari3_nltx i(insert) nltxpath pngpath [outpath]") 
        return
        
    inpath = sys.argv[2]
    if sys.argv[1].lower() == 'e':
        if len(sys.argv) < 4: outpath = inpath + ".png"
        else: outpath = sys.argv[3]
        extract_nltx(inpath, outpath)
    elif sys.argv[1].lower() == 'i':
        insertpath = sys.argv[3]
        if len(sys.argv) < 5: outpath = inpath + ".png"
        else: outpath = sys.argv[4]
        insert_nltx(inpath, insertpath, outpath)
    else: raise ValueError(f"invalid mode {sys.argv[0]}")

if __name__ =="__main__":
    # debug()
    main()
    pass