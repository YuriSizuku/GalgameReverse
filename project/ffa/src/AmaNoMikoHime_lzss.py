"""
parsing lzss compress file for for 天巫女姫, 
  v0.1, developed by devseed

"""

import os
import sys
import mmap
import struct
from typing import Union
from ctypes import CDLL, addressof, c_char, c_char_p, c_size_t

try:
    g_lzmadll = CDLL(os.path.join(os.path.dirname(sys.argv[0]), "liblzss20_64.dll"))
except FileNotFoundError as e:
    g_lzmadll = CDLL("./liblzss20_64.dll")
        
g_lzmadll.lzss_encode.argtypes = [c_char_p, c_char_p, c_size_t]
g_lzmadll.lzss_encode.restype = c_size_t
g_lzmadll.lzss_decode.argtypes = [c_char_p, c_char_p, c_size_t]
g_lzmadll.lzss_decode.restype = c_size_t

def decode_lzss(inobj: Union[str, memoryview], outpath="out"):
    fd = None
    if type(inobj) == str:
        fd = os.open(inobj, os.O_RDWR)
        data = mmap.mmap(fd, 0)
    else: data = inobj

    zsize, rawsize = struct.unpack("<II", data[0:8])
    bufsrc = c_char * (len(data) -8)
    bufdst = (c_char * rawsize)()
    dstsize = g_lzmadll.lzss_decode(
        bufsrc.from_buffer(data, 8), bufdst, zsize)

    if dstsize != rawsize:
        raise ValueError(f"decode data size wrong {dstsize:x}!={rawsize:x}")
    print("1123")

    if fd is not None: os.close(fd)
    if outpath:
      with open(outpath, 'wb') as fp:
        fp.write(bufdst.raw[:dstsize])
    return bufdst.raw, dstsize

def encode_lzss(inobj: Union[str, memoryview], outpath="out"):
    fd = None
    if type(inobj) == str:
        fd = os.open(inobj, os.O_RDWR)
        data = mmap.mmap(fd, 0)
    else: data = inobj

    bufsrc = c_char * (len(data))
    bufdst = (c_char * (len(data)))()
    dstsize = g_lzmadll.lzss_encode( 
        bufsrc.from_buffer(data), 
        c_char_p(addressof(bufdst)+8), len(data))
    bufdst[0:8] = struct.pack("<II", dstsize, len(data))
    
    if fd is not None: os.close(fd)
    if outpath:
      with open(outpath, 'wb') as fp:
        fp.write(bufdst[:dstsize+8])
    return bufdst, dstsize

def debug():
    decode_lzss(r"D:\Make\reverse\AmaNoMikoHime\extract\AmaNoMikoHime_SO4\G1WIN\g0002.SO4")
    # encode_lzss("./build/intermediate/sn.bin.dec")

def main():
    if len(sys.argv) < 3:
        print("AmaNoMikoHime_lzss e inpath [outpath]")
        print("AmaNoMikoHime_lzss d inpath [outpath]")
        return

    outpath = sys.argv[3] if len(sys.argv) > 3 else "out"
    if sys.argv[1].lower() == 'e':
        encode_lzss(sys.argv[2], outpath)
    elif sys.argv[1].lower() == 'd':
        decode_lzss(sys.argv[2], outpath)
    else: raise ValueError(f"unknow format {sys.argv[1]}")

if __name__ == '__main__':
    # debug()
    main()
    pass