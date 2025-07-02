"""
tool for krkr xp2 (xpk2) format
  v0.1, developed by devseed

tested games:
  GoddessGM (krkr v0.91)
"""

import sys
import mmap
import struct
import argparse
import zlib
from dataclasses import dataclass
from pathlib import Path
from typing import Tuple, List

# 58 50 4B 32 1A 04 00 00 1C 07 04 00 00 00 92

@dataclass
class XP2Header:
    magic = b""
    size1 = 0
    offset = 0 # content offset
    nentry = 0

# 04 00 00 1C 16 04 00 00 0E 0F 04 00 00 39 03 01
# 01 04 00 00 00 0B 62 67 6D 5C 6F 2D 31 2E 6D 69 // bgm\o-1.mid
# 64 64 01 08 00 77 2B A5 84 AA C3 01 00

@dataclass
class XP2Entry:
    offset = 0
    zsize = 0
    fsize = 0
    flag = False
    path = ""
    unknow1 = None
    unknow2 = None

def parse_xp2(data: memoryview, show_log=False) -> Tuple[XP2Header, List[XP2Entry]]:
    header = XP2Header()
    header.magic = data[:4]
    header.size1 = data[:5]
    header.offset, = struct.unpack(">I", data[0x6:0Xa])
    header.nentry, = struct.unpack(">I", data[0xb:0xf])
    assert header.magic == b'XPK2', f"{header.magic} is not XPK2"
    
    cur = 0xf
    entries = []
    for i in range(header.nentry):
        entry = XP2Entry()

        _,entry.offset,_ , entry.zsize, _, entry.fsize = struct.unpack(">BIBIBI", data[cur: cur+15])
        cur += 15

        cur += data[cur]
        entry.flag = data[cur]
        cur += 2
        pathlen, = struct.unpack(">I", data[cur: cur+4])
        cur += 4
        entry.path = data[cur: cur+pathlen].decode()
        cur += pathlen
        entry.unknow1, entry.unknow2 = data[cur: cur+4], data[cur+4: cur+12]
        cur += 12
        
        entries.append(entry)

        if show_log:
            print(f"{i+1}/{header.nentry} {entry.path} flag={entry.flag} offset=0x{entry.offset:x} zsize=0x{entry.zsize:x} fsize=0x{entry.fsize:x}")

    return header, entries

def unpack_xp2(inpath, outdir="out"):
    fp = open(inpath, "rb")
    data = mmap.mmap(fp.fileno(), 0, access=mmap.ACCESS_READ)
    
    header, entries = parse_xp2(data)
    
    for i, entry in enumerate(entries):
        if entry.offset + entry.zsize > len(data):
            print(f"SKIP {i+1}/{header.nentry} extract {entry.path}")
            continue
        content = data[entry.offset: entry.offset + entry.zsize]
        if entry.fsize != entry.zsize: content = zlib.decompress(content)
        assert len(content) == entry.fsize, "decompress failed"
        print(f"EXTRACT {i+1}/{header.nentry} {entry.path}")

        outpath = Path(outdir) / entry.path 
        if not outpath.parent.exists():  outpath.parent.mkdir(parents=True)
        with open(outpath, "wb") as fp:
            fp.write(content)

    data.close()
    fp.close()

def pack_xp2(indir, outpath):
    raise NotImplementedError()

def cli(cmdstr=None):
    p = argparse.ArgumentParser(description="pack or unpack krkr1 xp3 file, v0.1, by devseed")
    p.add_argument("method", choices=["pack", "unpack"])
    p.add_argument("inpath", help="file path or dir path")
    p.add_argument("-o", "--outpath", default="out")
    if cmdstr is None and len(sys.argv) < 2:
        p.print_help()
        return

    args = p.parse_args(cmdstr.split(" ") if cmdstr is not None else None)
    print(args)
    if args.method == "unpack":
        unpack_xp2(args.inpath, args.outpath)
    elif args.method == "pack":
        pack_xp2(args.inpath, args.outpath)

if __name__ == "__main__":
    cli()