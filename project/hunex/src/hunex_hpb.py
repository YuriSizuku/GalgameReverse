"""
for decoding hpb(hph) format in hunex engine
  v0.1, developed by devseed

tested game:
    明治東亰恋伽

"""

import os
import sys
import ctypes
from zlib import crc32

from hunex_hlzs import decode_hlzs

class hpac_header_t(ctypes.Structure):
    _fields_ = [
        ("id", ctypes.c_uint32), 
        ("version", ctypes.c_uint32), 
        ("count", ctypes.c_int32), 
        ("size", ctypes.c_uint32), 
        ("nameOffset", ctypes.c_uint32), 
        ("padding", ctypes.c_void_p), 
    ]

class hpac_entry_t(ctypes.Structure):
    _fields_ = [
        ("offset", ctypes.c_int64), 
        ("key", ctypes.c_uint32), 
        ("fileSize", ctypes.c_uint32), 
        ("meltSize", ctypes.c_uint32), 
        ("fileCRC", ctypes.c_uint32), 
        ("meltCRC", ctypes.c_uint32), 
    ]

def extract_hpb(hpbpath, outdir="out"):
    hphpath = os.path.splitext(hpbpath)[0] + ".hph"
    inname = os.path.basename(os.path.splitext(hpbpath)[0])
    with open(hphpath, "rb") as fp:
        hphbuf = fp.read()
    with open(hpbpath, "rb") as fp:
        hpbbuf = memoryview(fp.read())
    if not os.path.exists(outdir):
        os.makedirs(outdir)

    hpc_header = hpac_header_t.from_buffer_copy(hphbuf)
    assert(hpc_header.id == int.from_bytes(b"HPAC", "little", signed=False))
    print(f"[extract_hpb] inpath={hpbpath} outdir={outdir} count={hpc_header.count}")
    for i in range(hpc_header.count):
        offset = ctypes.sizeof(hpac_header_t) + i*ctypes.sizeof(hpac_entry_t)
        hpac_entry = hpac_entry_t.from_buffer_copy(hphbuf, offset)
        if hpac_entry.fileSize == 0: continue
        print(f"[extract_hpb] no={i} offset=0x{hpac_entry.offset:08x}"
              f" fileSize=0x{hpac_entry.fileSize:08x} meltSize=0x{hpac_entry.meltSize:08x}"
              f" fileCRC={hpac_entry.fileCRC:08x} meltCRC={hpac_entry.meltCRC:08x}")
        inbuf = hpbbuf[hpac_entry.offset: hpac_entry.offset + hpac_entry.fileSize]
        outbuf = inbuf
        assert(crc32(inbuf) == hpac_entry.fileCRC)
        if inbuf[0:4] == b'HLZS': outbuf = decode_hlzs(inbuf)
        assert(len(outbuf) == hpac_entry.meltSize)
        assert(crc32(outbuf) ==  hpac_entry.meltCRC)
        outpath = os.path.join(outdir, inname + f"_{hpac_entry.offset:08x}")
        with open(outpath, "wb") as fp:
            fp.write(outbuf)

def main(argv):
    if len(argv) < 2:
        print("hunex_hpb inpath [outdir]")
        return
    inpath = argv[1]
    outdir = os.path.splitext(inpath)[0] + "_extract" if len(argv) < 3 else argv[2]
    extract_hpb(inpath, outdir)

if __name__ == "__main__":
    main(sys.argv)
