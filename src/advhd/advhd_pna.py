"""
export or import pna for willplus advhd, 
tested in BlackishHouse (v1.6.2.1)
    v0.1.1, developed by devseed
"""

import os
import sys
import struct
import numpy as np
from PIL import Image
from io import SEEK_END, SEEK_SET, BytesIO
from glob import glob
from collections import namedtuple
from typing import List

pngentry_t = namedtuple('pngentry_t', ['x', 'y', 'w', 'h', 'offset', 'size'])

def parse_pna(data):
    pngentries: List[pngentry_t] = []
    n = int.from_bytes(data[0x10: 0x14], 'little', signed=False)
    pngoffset = 0x14 + n*0x28
    for i in range(n):
        cur = 0x14 + i*0x28 + 0x8
        x, y, w, h = struct.unpack("<4I", data[cur: cur+0x10])
        cur = 0x14 + i*0x28 + 0x24
        size, = struct.unpack("<I", data[cur: cur+0x4])
        pngentries.append(pngentry_t(x, y, w, h, pngoffset, size))
        pngoffset += size
    return pngentries

def export_pna(inpath, outdir="./out"):
    with open(inpath, 'rb') as fp:
        data = fp.read()
    entries = parse_pna(data)

    if outdir!="":
        inname = os.path.basename(inpath)
        inname = os.path.splitext(inname)[0]
        for i, entry in enumerate(entries):
            if entry.size == 0: continue
            outpath = os.path.join(outdir, f"{inname}_{i:03d}.png")
            with open(outpath, 'wb') as fp:
                fp.write(data[entry.offset: entry.offset + entry.size])
            print("read", entry)

    return entries

def import_pna(indir, orgpath, outpath="./out.pna"):
    with open(orgpath, 'rb') as fp:
        data = fp.read()
    entries = parse_pna(data)
    
    # prepare paths
    bufio = BytesIO(data[0: 0x14 + 0x28*len(entries)])
    bufio.seek(0, SEEK_END)
    inpaths = glob(os.path.join(indir, "*.png"))
    innames = [os.path.basename(x) for x in inpaths]
    orgname = os.path.basename(orgpath)
    orgname = os.path.splitext(orgname)[0]
    
    # write content
    for i, entry in enumerate(entries):
        inname = f"{orgname}_{i:03d}.png"
        if inname in innames:
            inpath = os.path.join(indir, inname)
            print(f"update {inname}"
                f", offset 0x{entry.offset:x}->0x{bufio.tell():x}"
                f", size {entry.size:x}->{os.stat(inpath).st_size:x}")
            img = np.array(Image.open(inpath))
            if img.shape[2] > 3: # fix alpha 0 to all pixel 0
                amask = np.expand_dims(img[:, :, 3] > 0, axis=2)
                img = img * amask
            _imgio = BytesIO()
            Image.fromarray(img).save(_imgio, format='png')
            bufio.write(_imgio.getbuffer())
            entries[i] = pngentry_t(
                entry.x, entry.y, entry.w, entry.h, 
                bufio.tell(), len(_imgio.getbuffer()))
        else:
            bufio.write(data[entry.offset: entry.offset + entry.size])

    # write header
    for i, entry in enumerate(entries):
        offset = 0x14 + i*0x28 + 0x24 
        bufio.seek(offset, SEEK_SET)
        bufio.write(int.to_bytes( # only update size
            entry.size, 4, 'little', signed=False))
    
    if outpath!="":
        with open(outpath, 'wb') as fp:
            fp.write(bufio.getbuffer())

    return bufio.getbuffer()

def debug():
    # export_pna("./build/intermediate/SysGraphic/Sys_CharSelect.pna")
    import_pna("./buildv2.1/intermediate/SysGraphic_png/Sys_title", "./buildv2.1/intermediate/SysGraphic/Sys_title.pna")
    pass

def main():
    if len(sys.argv) < 3:
        print("advhd_pna e inpath [outdir]")
        print("advhd_pna i indir orgpath [outpath]")
        return
    if sys.argv[1].lower() == 'e':
        outpath = sys.argv[3] if len(sys.argv) > 3 else "./out"
        export_pna(sys.argv[2], outpath)
    elif sys.argv[1].lower() == 'i':
        outpath = sys.argv[4] if len(sys.argv) > 4 else "out.pna"
        import_pna(sys.argv[2], sys.argv[3], outpath)
    else: raise ValueError(f"unknow format {sys.argv[1]}")

if __name__ == '__main__':
    # debug()
    main()
    pass

"""
history:
v0.1, support BlackishHouse (v1.6.2.1)
v0.1.1, fix png alpha problem
"""