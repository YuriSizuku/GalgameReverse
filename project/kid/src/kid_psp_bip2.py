"""
encode or decode bip files (lzss compress), using cffi 
  v0.1, developed by devseed

  tested games:
  ULJM06002 想いのかけら －Close to－
"""

import os
import sys
import struct
from mmap import mmap, ACCESS_READ, ACCESS_COPY
from typing import List

import shutil
import tempfile
from cffi import FFI

try:
    import pylzss
except ImportError:
    ffi = FFI()
    ffi.cdef("""
        int lzss_decode(uint8_t *dst, uint8_t *src, uint32_t srclen);
        uint8_t *lzss_encode(uint8_t *dst, uint32_t dstlen, uint8_t *src, uint32_t srcLen);            
    """)

    curdir = os.path.dirname(os.path.abspath(__file__))
    ffi.set_source("pylzss", """
      #include "lzss.h"
    """, include_dirs=[curdir])
    tmpdir = tempfile.TemporaryDirectory()
    pydpath = ffi.compile(tmpdir.name, verbose=True)
    shutil.copy(pydpath, curdir)
    tmpdir.cleanup()
    import pylzss
    
def decode_bip(data: memoryview, outpath=None):
    ffi = FFI()
    zsize = len(data) - 4
    rawsize: int = struct.unpack_from("<I", data, 0)[0]
    outdata = bytearray(b'\x00' * rawsize)
    bufsrc = ffi.from_buffer(data[4:])
    bufdst = ffi.from_buffer(outdata)
    dstsize = pylzss.lib.lzss_decode(bufdst, bufsrc, zsize)
    if outpath:
        with open(outpath, 'wb') as fp: 
            fp.write(outdata)
    assert(dstsize == len(outdata))
    return outdata

def encode_bip(data: memoryview, outpath=None):
    ffi = FFI()
    rawsize = len(data)
    outsize = 2*rawsize
    outdata = memoryview(bytearray(b'\x00' * (outsize + 4)))
    outdata[:4] = struct.pack("<I", rawsize)
    bufsrc = ffi.from_buffer(data)
    bufdst = ffi.from_buffer(outdata[4:])
    pbufdstend = pylzss.lib.lzss_encode(bufdst, ffi.sizeof(bufdst), bufsrc, ffi.sizeof(bufsrc))
    zsize = pbufdstend - ffi.cast("uint8_t *", bufdst)
    if outpath:
        with open(outpath, 'wb') as fp: 
            fp.write(outdata[:zsize + 4])
    return outdata[:zsize+4]

def cli(argv: List[str]):
    def cmd_help():
        print("kid_psp_bip d bippath [decpath] # decode bip")
        print("kid_psp_bip e decpath [bippath] # encode bip")

    def cmd_decode():
        decode_bip(data, outpath)

    def cmd_encode():
        encode_bip(data, outpath)

    if len(argv) < 3: cmd_help(); return
    
    cmdtype = argv[1].lower()
    inpath = argv[2]
    outpath = 'out' if len(argv) < 4 else argv[3]

    fp = open(inpath, 'rb') # ACCESS_COPY to enable from_buffer
    data = mmap(fp.fileno(), 0, access=ACCESS_READ | ACCESS_COPY)
    if cmdtype == 'd': cmd_decode()
    elif cmdtype == 'e': cmd_encode()
    else: raise ValueError(f'unsupported cmdtype {argv[1]}!')
    data.close()
    fp.close()

def debug():
    cli([__file__, "d", "tmp/C09A.BIP", "tmp/C09A_dec.BIP"])
    cli([__file__, "e", "tmp/C09A_dec.BIP", "tmp/C09A_rebuild.BIP"])

if __name__ == '__main__':
    debug()
    cli(sys.argv)