"""
to export or import sn.bin (after decompress) for Narcissus psp, 
  v0.1, developed by devseed
"""

import os
import sys
import struct
from glob import glob
from io import SEEK_END, SEEK_SET, BytesIO
from typing import List
from collections import namedtuple

snidx_t = namedtuple("narsn_indexnode", ['offset', 'size'])

def load_snidxs(data) -> List[snidx_t]:
    end = int.from_bytes(data[0:4], 'little', signed=False)
    cur = 0
    narsn_indexs: List[snidx_t] = []
    while cur < end:
        offset, size = struct.unpack("<2I", data[cur: cur+8])
        narsn_indexs.append(snidx_t(offset, size))
        cur += 0x10
    return narsn_indexs

def dump_snidxs(narsn_indexs: List[snidx_t]):
    dataio = BytesIO()
    for t in narsn_indexs:
        dataio.write(struct.pack("<4I", t.offset, t.size, 0, 0))
    return dataio.getbuffer()

def export_sn(inpath, outdir="./out"):
    with open(inpath, 'rb') as fp:
        data = fp.read()
    narsn_indexs = load_snidxs(data)

    if outdir != "./out":
        name = os.path.splitext(os.path.basename(inpath))[0]
        for i, t in enumerate(narsn_indexs):
            outpath = os.path.join(outdir, f"{name}_{i:02d}.bin")
            with open(outpath, 'wb') as fp:
                fp.write(data[t.offset: t.offset + t.size])

    return narsn_indexs

def import_sn(indir, orgpath, outpath="out.bin"):
    # load origin sn.bin
    with open(orgpath, 'rb') as fp:
        orgdata = fp.read()
    narsn_indexs = load_snidxs(orgdata)
    
    # import file data
    shift = 0
    align = 0x10
    bufio = BytesIO(len(narsn_indexs)*0x10*b'\x00')
    bufio.seek(0, SEEK_END)
    filelist: List[str] = glob(os.path.join(indir, "*.bin"))
    for i, t in enumerate(narsn_indexs):
        findidx = -1
        for j, file in enumerate(filelist):
            if file.find(f"{i:02d}.bin") != -1:
                findidx = j
                break
        if findidx == -1: 
            bufio.write(orgdata[t.offset: t.offset + t.size])
            addsize = 0
        else:
            with open (filelist[findidx], 'rb') as fp:
                data = fp.read()
            padsize = 0
            if len(data)%align: 
                padsize = align - len(data)%align
            bufio.write(data)
            bufio.write(b'\x00' * padsize)
            addsize = len(data) + padsize - t.size

        if shift != 0 or addsize != 0:
            print(f"{i}, {filelist[findidx]}, "
                    f"offset {t.offset:x}->{t.offset+shift:x}, "
                    f"size {t.size:x}->{t.size+addsize:x}")
        narsn_indexs[i] = snidx_t(t.offset+shift, t.size + addsize)
        shift += addsize
        assert(narsn_indexs[i].offset + narsn_indexs[i].size == bufio.tell())

    # rebuild the index
    bufio.seek(0, SEEK_SET)
    bufio.write(dump_snidxs(narsn_indexs))

    if outpath!="":
        with open(outpath, 'wb') as fp:
            fp.write(bufio.getbuffer())

    return bufio.getbuffer()

def debug():
    export_sn("./build/intermediate/sn.bin.dec", "./build/intermediate/sn")
    import_sn("./build/intermediate/sn_rebuild/", "./build/intermediate/sn.bin.dec", "./build/intermediate/sn_rebuild.bin.dec")
    pass

def main():
    if len(sys.argv) < 3:
        print("Narcissus_sn e inpath [outdir]")
        print("Narcissus_sn i indir orgpath [outpath]")
        return
    if sys.argv[1].lower() == 'e':
        outdir = sys.argv[3] if len(sys.argv) > 3 else "./out"
        export_sn(sys.argv[2], outdir)
    elif sys.argv[1].lower() == 'i':
        outpath = sys.argv[4] if len(sys.argv) > 4 else "out.bin"
        import_sn(sys.argv[2], sys.argv[3], outpath)
    else: raise ValueError(f"unknow format {sys.argv[1]}")

if __name__ == '__main__':
    # debug()
    main()
    pass