"""
for decoding hlzs format (script_dialog_xx.hdlg) in hunex engine
  v0.1, developed by devseed

tested game:
    明治東亰恋伽

"""

import sys
import io
import ctypes

import numba
import numpy as np
from numba import njit, uint8, int32
readonly = lambda dtype, dim: numba.types.Array(dtype, dim, "C", True)

class hlzs_header_t(ctypes.Structure):
    _fields_ = [
        ("id", ctypes.c_uint32), 
        ("version", ctypes.c_uint32), 
        ("encodeSize", ctypes.c_uint32), 
        ("decodeSize", ctypes.c_uint32), 
    ]

def decode_lzs(inbuf: memoryview, DICT_SIZE=0x1000, MAX_LEN=0x12) -> memoryview:
    dictbuf = memoryview(bytearray(b'\x00' * DICT_SIZE))
    outio = io.BytesIO() # outbuf sync with dict
    flag8 = 1 # flags for next 8 itmes
    inpos, dictpos = 0, 0
    
    while inpos < len(inbuf):
        if flag8 == 1:
            flag8 = inbuf[inpos] | 0x100
            inpos += 1
        flag = flag8 & 0x1
        flag8 >>= 1
        if flag: # direct copy
            c = inbuf[inpos: inpos+1]
            inpos += 1
            outio.write(c)
            dictbuf[dictpos: dictpos+1] = c
            dictpos = (dictpos + 1) & (DICT_SIZE -1) # circle dict buf write
        else: # dict copy
            low, high = inbuf[inpos: inpos+2]
            inpos += 2
            wordpos, wordsize = ((high & 0xf0) << 4 | low) + MAX_LEN, (high & 0x0f) + 3
            for i in range(wordsize):
                pos = (wordpos + i) & (DICT_SIZE -1)
                c = dictbuf[pos: pos+1]
                outio.write(c)
                dictbuf[dictpos: dictpos+1] = c # write back to dict
                dictpos = (dictpos + 1) & (DICT_SIZE -1)

    return outio.getbuffer()

@njit([int32(readonly(uint8, 1), int32,uint8[:], int32, uint8[:], int32)])
def decode_lzs_fast(inbuf, insize, dictbuf, dictsize, outbuf, outsize):
    MAX_LEN = 0x12
    flag8 = 1 # flags for next 8 itmes
    inpos, outpos, dictpos = 0, 0, 0

    while inpos < insize:
        if outpos >= outsize: return 0
        if flag8 == 1:
            flag8 = inbuf[inpos] | 0x100
            inpos += 1
        flag = flag8 & 0x1
        flag8 >>= 1
        if flag: # direct copy
            c = inbuf[inpos]
            inpos += 1
            outbuf[outpos] = c
            outpos += 1
            dictbuf[dictpos] = c
            dictpos = (dictpos + 1) & (dictsize -1) # circle dict buf write
        else: # dict copy
            low, high = inbuf[inpos], inbuf[inpos+1]
            inpos += 2
            wordpos, wordsize = ((high & 0xf0) << 4 | low) + MAX_LEN, (high & 0x0f) + 3
            for i in range(wordsize):
                pos = (wordpos + i) & (dictsize -1)
                c = dictbuf[pos]
                outbuf[outpos] = c
                outpos += 1
                dictbuf[dictpos] = c # write back to dict
                dictpos = (dictpos + 1) & (dictsize -1)

    return outpos

def decode_hlzs(hlzsbuf: memoryview, use_fast_lzs=True) -> memoryview:
    hlzs_header = hlzs_header_t.from_buffer_copy(hlzsbuf)
    assert(hlzs_header.id == int.from_bytes(b"HLZS", "little", signed=False))
    if use_fast_lzs:
        inbuf = np.frombuffer(hlzsbuf, dtype=np.uint8, offset=0x20, count=hlzs_header.encodeSize)
        outbuf = np.zeros(hlzs_header.decodeSize, dtype=np.uint8)
        dictbuf = np.zeros(0x1000, dtype=np.uint8)
        outsize = decode_lzs_fast(inbuf, inbuf.nbytes, dictbuf, dictbuf.nbytes, outbuf, outbuf.nbytes)
        assert(outsize == hlzs_header.decodeSize)
        outbuf = memoryview(outbuf)
    else:
        inbuf = memoryview(hlzsbuf[0x20: 0x20 + hlzs_header.encodeSize])
        outbuf = decode_lzs(inbuf)
        assert(len(outbuf) == hlzs_header.decodeSize)
    
    return outbuf

def main(argv):
    if len(argv) < 2:
        print("hunex_hlzs inpath [outpath]")
        return
    inpath = argv[1]
    outpath = inpath + ".dec" if len(argv) < 3 else argv[2]
    with open(inpath, 'rb') as fp:
        inbuf = memoryview(fp.read())
    outbuf = decode_hlzs(inbuf)
    with open(outpath, "wb") as fp:
        fp.write(outbuf)

if __name__ == "__main__":
    main(sys.argv)