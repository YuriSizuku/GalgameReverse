"""
parsing PT1 image file rgb24 format for 天巫女姫, 
  v0.1, developed by devseed
  
"""

import os
import sys
import struct
import numpy as np
from io import BytesIO
from PIL import Image

import amanomiko_lzss as amalzss

class pt1_t(struct.Struct):
    def __init__(self, data):
        super().__init__('6I')
        self.frombytes(data)

    def frombytes(self, data):
        self.data = data
        (self.type, self.reserve1, 
        self.x, self.y, self.height, self.width) = \
                self.unpack_from(self.data, 0)

    def tobytes(self):
        self.x, self.y, 
        self.pack_into(self.data, 0, 
            self.type, self.reserve1, self.x, self.y, 
            self.height, self.width)
        return self.data

def export_pt1(pt1path, outpath="out.png"):
    """
    this function has problem except type v0,
    see https://github.com/morkt/PopulateLzssFrame/blob/master/ArcFormats/Ffa/ImagePT1.cs
    """

    with open(pt1path, 'rb') as fp:
        data = memoryview(bytearray(fp.read()))
    pt1 = pt1_t(data)

    rawdata, rawsize = amalzss.decode_lzss(data[pt1.size: ], outpath=outpath)
    if rawsize != pt1.height * pt1.width * 3:
        raise ValueError(f"pt1 decode error: {rawsize}!={pt1.height}X{pt1.width}X3")
    return rawdata
    
def import_pt1(imgpath, orgpt1path,  outpath="out.PT1"):
    """
    only support for type0 rebuild
    """

    with open(orgpt1path, 'rb') as fp:
        data = bytearray(fp.read(0x18))
    pt1 = pt1_t(data)
    pt1.type = 0
    
    bufio = BytesIO()
    bufio.write(pt1.tobytes())
    bgr = np.array(Image.open(imgpath))
    bgr = bgr[:,:, [2,1,0]]
    buf, zsize = amalzss.encode_lzss(memoryview(bgr.flatten()), "")
    bufio.write(buf[:zsize + 8])

    if outpath != "":
        with open(outpath, 'wb') as fp:
            fp.write(bufio.getbuffer())
    return bufio.getbuffer()

def debug():
    export_pt1("./build/intermediate/G1WIA/EHTB0101.PT1")
    # import_pt1("./build/intermediate/G1WIA_png/G1_TIT0.png", "./build/intermediate/G1WIA/G1_TIT0.PT1")
    pass

def main():
    if len(sys.argv) < 3:
        print("PT1 e pt1path [outpath]")
        print("PT1 i imgpath orgpt1path [outpath]")
        return
    if sys.argv[1].lower() == 'e':
        outpath = sys.argv[3] if len(sys.argv) > 3 else "out.txt"
        export_pt1(sys.argv[2], outpath)
    elif sys.argv[1].lower() == 'i':
        outpath = sys.argv[4] if len(sys.argv) > 4 else "out.bin"
        import_pt1(sys.argv[2], sys.argv[3], outpath)
    else: raise ValueError(f"unknow format {sys.argv[1]}")

if __name__ == '__main__':
    # debug()
    main()
    pass