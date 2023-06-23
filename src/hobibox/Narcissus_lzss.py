"""
parsing lzss structure with header for Narcissus psp, 
  v0.1, developed by devseed

"""

import os
import sys
import mmap
from ctypes import CDLL, addressof, c_char, c_char_p, c_size_t

try:
    g_lzmadll = CDLL(os.path.join(os.path.dirname(
        sys.argv[0]), "liblzss64.dll"))
except FileNotFoundError as e:
    g_lzmadll = CDLL("./liblzss64.dll")
g_lzmadll.lzss_encode.argtypes = [c_char_p, c_char_p, c_size_t]
g_lzmadll.lzss_encode.restype = c_size_t
g_lzmadll.lzss_decode.argtypes = [c_char_p, c_char_p, c_size_t]
g_lzmadll.lzss_decode.restype = c_size_t

def decode_lzss(inpath, outpath="out"):
    fd = os.open(inpath, os.O_RDWR)
    data = mmap.mmap(fd, 0)
    rawsize = int.from_bytes(data[0:4], 'little', signed=False)
    bufsrc = c_char * (len(data) -4)
    bufdst = (c_char * rawsize)()
    dstsize = g_lzmadll.lzss_decode(
        bufsrc.from_buffer(data, 4), bufdst, len(data)-4)
    os.close(fd)

    if dstsize != rawsize:
        raise ValueError(f"decode data size wrong {dstsize:x}!={rawsize:x}")

    if outpath:
      with open(outpath, 'wb') as fp:
        fp.write(bufdst.raw[:dstsize])
    return bufdst.raw, dstsize

def encode_lzss(inpath, outpath="out"):
    fd = os.open(inpath, os.O_RDWR)
    data = mmap.mmap(fd, 0)
    bufsrc = c_char * (len(data))
    bufdst = (c_char * (len(data)))()
    dstsize = g_lzmadll.lzss_encode( 
        bufsrc.from_buffer(data), 
        c_char_p(addressof(bufdst)+4), len(data))
    bufdst[0:4] = int.to_bytes(
        len(data), 4, 'little', signed=False)
    os.close(fd)
    if outpath:
      with open(outpath, 'wb') as fp:
        fp.write(bufdst[:dstsize+4])
    return bufdst, dstsize

def debug():
    decode_lzss("./build/intermediate/sn.bin")
    encode_lzss("./build/intermediate/sn.bin.dec")

def main():
    if len(sys.argv) < 3:
        print("Narcissus_lzss e inpath [outpath]")
        print("Narcissus_lzss d inpath [outpath]")
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