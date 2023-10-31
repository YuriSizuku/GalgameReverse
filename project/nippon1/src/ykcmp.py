"""
A python implementation for 
decompressing and compressing the ykcmp compress structure
according to https://github.com/iltrof/ykcmp/wiki/Decompression
    developed by devseed, v0.1
"""

import struct
from io import BytesIO

class ykcmp_t(struct.Struct):
    def __init__(self, data=None):
        super().__init__('<8s3I')
        self.frombytes(data)

    def frombytes(self, data):
        if data==None:
            data = b'YKCMP_V1\x04\x00\x00\x00' + b'\x00'*8
        (self.magic,
         self.type, # 04 00 00 00
         self.ykcmpsize,
         self.rawsize) = self.unpack_from(data, 0)
        self.content = data[0x14:]

    def tobytes(self):
        data = bytearray(self.ykcmpsize + 0x14)
        self.pack_into(data, 0, 
            self.magic,
            self.type,
            self.ykcmpsize,
            self.rawsize)
        data[0x14:] = self.content
        return data

def decompress_ykcmpv1(data, outpath=""):
    ykcmp = ykcmp_t(data)
    if ykcmp.magic != b'YKCMP_V1':
        raise ValueError("unsupport format ", ykcmp.magic)
    
    resdata = bytearray(ykcmp.rawsize)
    orgpos = 0
    dstpos = 0
    while orgpos < len(ykcmp.content):
        c0 = ykcmp.content[orgpos]
        if c0 < 0x80: # forward copy XX
            offset = 1
            size = c0
            resdata[dstpos: dstpos+size] = \
                ykcmp.content[orgpos+offset: orgpos+offset+size]
            orgpos += size + 1
            dstpos += size
        else:
            if c0 < 0xc0: # XY, backward Y+1, copy X-0x8+1
                offset = (c0&0xf) + 1
                size = (c0>>4) - 0x8 + 1
                orgpos += 1
            elif c0 < 0xe0: # XX YY, backward YY+1, copy XX-0xc0+2 
                c1 = ykcmp.content[orgpos+1]
                offset = c1 + 1
                size = c0 - 0xc0 + 2
                orgpos += 2
            else: # XX XY YY, backward YYY+1, copy XXX-0xe00+3
                c1 = ykcmp.content[orgpos+1]
                c2 = ykcmp.content[orgpos+2]
                offset = ((c1&0xf)<<8) + c2 + 1
                size = ((c0<<4) + (c1>>4)) - 0xe00 + 3 
                orgpos += 3
            resdata[dstpos: dstpos+size] = \
                resdata[dstpos-offset: dstpos-offset+size]
            dstpos += size

    if dstpos!=ykcmp.rawsize:
        raise AssertionError(f"decompress size error!")
    if outpath!="":
        with open(outpath, 'wb') as fp:
            fp.write(resdata)
    return resdata

def compress_ykcmpv1(data, outpath=""):
    ykcmp = ykcmp_t()
    _bufio = BytesIO()
    for i in range(0, len(data), 0x7f):
        size = 0x7f
        if i + size> len(data): size = len(data) - i
        _bufio.write(bytes([size]))
        _bufio.write(data[i: i+size])

    ykcmp.content = _bufio.getbuffer()
    ykcmp.rawsize = len(data)
    ykcmp.ykcmpsize = 0x14 + len(ykcmp.content)
    resdata = ykcmp.tobytes()
    if outpath!="":
        with open(outpath, 'wb') as fp:
            fp.write(resdata)
    return resdata