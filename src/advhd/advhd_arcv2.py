"""
export or build arc v2 for willplus advhd 
tested in BlackishHouse (v1.6.2.1)
    v0.1, developed by devseed
"""

import os
import sys
import mmap
import struct
from io import BytesIO
from collections import namedtuple
from typing import List, Tuple

advhdv2_fileentry_t = namedtuple('advhdentry_t', ['size', 'offset', 'name'])

def ror(d, n):
    n &= 7
    return (d>>n | d<<(8-n)) & 0xff

def rol(d, n):
    n &= 7
    return (d<<n | d>>(8-n)) & 0xff

def parse_arc(data: bytes) -> Tuple[int, List[advhdv2_fileentry_t]]:
    n, index_size = struct.unpack("<II", data[0:8])
    cur = 8
    adventries: List[advhdv2_fileentry_t] = []
    while cur < index_size + 8:
        size, offset = struct.unpack("<II", data[cur:cur+8])
        cur += 8
        end = cur
        while(end < len(data)):
            if(data[end]==0 and data[end+1]==0): break
            end += 2
        name = data[cur: end].decode('utf-16-le')
        cur = end + 2
        adventries.append(advhdv2_fileentry_t(size, offset, name))
    return index_size, adventries

def export_arc(inpath, outdir="./out"):
    fd = os.open(inpath, os.O_RDONLY)
    data = mmap.mmap(fd, 0, access=mmap.ACCESS_READ)
    index_size, entries = parse_arc(data)

    if outdir!="":
        for entry in entries:
            outpath = os.path.join(outdir, entry.name)
            with open(outpath, 'wb') as fp:
                start = entry.offset + index_size + 8
                end = start + entry.size
                targetbytes = data[start: end]
                if os.path.splitext(entry.name)[1].lower() == '.ws2':
                    targetbytes = bytes(map(
                        lambda x: ror(x, 2), targetbytes))
                fp.write(targetbytes)
                print("read", entry)

    data.close()
    os.close(fd)
    return index_size, entries

def build_arc(indir, outpath="out.arc"):
    # prepare index
    offset = 0
    index_size = 0
    entries: List[advhdv2_fileentry_t] = []
    names = os.listdir(indir)
    for name in names:
        inpath = os.path.join(indir, name)
        size = os.stat(inpath).st_size
        entries.append(advhdv2_fileentry_t(size, offset, name))
        offset += size
        index_size +=  8 + len(name)*2 + 2

    # write file index
    bufio = BytesIO()
    bufio.write(struct.pack("<II", len(entries), index_size))
    for entry in entries:
        bufio.write(struct.pack("<II", entry.size, entry.offset))
        bufio.write(entry.name.encode('utf-16-le'))
        bufio.write(b'\x00\x00')
    assert(bufio.tell()==index_size + 8)
    
    # write file content
    for entry in entries:
        inpath = os.path.join(indir, entry.name)
        with open(inpath, 'rb') as fp:
            targetbytes = fp.read()
            if os.path.splitext(entry.name)[1].lower() == '.ws2':
                targetbytes = bytes(map(
                    lambda x: rol(x, 2), targetbytes))
        bufio.write(targetbytes)
        assert(bufio.tell()== index_size + 8 + entry.size + entry.offset)
        print("write", entry)
    
    if outpath:
        with open(outpath, 'wb') as fp:
            fp.write(bufio.getbuffer())

    return bufio.getbuffer()

def debug():
    pass

def main():
    if len(sys.argv) < 3:
        print("advhd_arcv2 e inpath [outdir]")
        print("advhd_arcv2 b indir  [outpath]")
        return
    if sys.argv[1].lower() == 'e':
        outpath = sys.argv[3] if len(sys.argv) > 3 else "./out"
        export_arc(sys.argv[2], outpath)
    elif sys.argv[1].lower() == 'b':
        outpath = sys.argv[3] if len(sys.argv) > 3 else "out.arc"
        build_arc(sys.argv[2], outpath)
    else: raise ValueError(f"unknow format {sys.argv[1]}")

if __name__ == '__main__':
    # debug()
    main()
    pass