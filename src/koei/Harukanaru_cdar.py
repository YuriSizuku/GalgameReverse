"""
for parsing cdvdar (type v4) structure of koei, 
tested by 遙かなる時空の中で～八葉抄
  v0.1, developed by devseed


0x0~0x8 magic 4, version 4 // 43 44 41 52, 04 00 00 00 // CDAR
0x8~0x10 filecount 4, hash 4 // 0x790, 4 * 0x790 = 1e40

// zsize != size, use zlib to decompress 
[hash 4] * filecount
[offset 4 size 4 zsize 4] * filecount

"""

import os
import sys
import zlib
import mmap
import struct
from collections import namedtuple
from typing import List

class cdar_t(struct.Struct):
    cdar_entry = namedtuple('cdar_entry', 
            ['fhash', 'offset', 'size', 'zsize'])

    def __init__(self, data: bytes):
        super().__init__("<4I")
        self.frombytes(data)

    def frombytes(self, data: bytes):
        self.data = data
        (self.magic, self.version, 
        self.count, self.hash) = \
        self.unpack_from(data)
        
        self.entries: List[cdar_t.cdar_entry] = []
        _offset1 = self.size
        _offset2 = _offset1 + self.count*4
        for i in range(self.count):
            _bytes = data[_offset1 + i*4: _offset1 + (i+1)*4]
            fhash = int.from_bytes(_bytes, 'little', signed=False)
            _bytes = data[_offset2 + i*12: _offset2 + (i+1)*12] 
            offset, size, zsize = struct.unpack("<3I", _bytes)
            entry = cdar_t.cdar_entry(fhash, offset, size, zsize)
            self.entries.append(entry)

def export_cdar(inpath, outdir="./OUT", recursive=True):
    extset = {b'CDAR', b'TIM2'}
    fd = os.open(inpath, os.O_RDWR)
    data = mmap.mmap(fd, 0)

    cdar = cdar_t(data)
    if outdir != "":
        if not os.path.exists(outdir):
            os.makedirs(outdir)

        for entry in cdar.entries:
            entry_data = data[entry.offset: entry.offset+entry.zsize]
            if entry.zsize != entry.size:
                entry_data = zlib.decompress(entry_data)
            
            if entry_data[0:4] in extset:
                ext = "." + entry_data[0:4].decode()
            else: ext = ""
            outpath = os.path.join(
                outdir, f"{entry.fhash:08x}{ext}")
            with open(outpath, 'wb') as fp:
                fp.write(entry_data)
                print(f"{outpath}, "
                f"fhash={entry.fhash:08x} offset={entry.offset:x} "
                f"size={entry.size:x} zsize={entry.zsize:x} extraced!")
            
            if recursive and entry_data[0:4] == b'CDAR':
                export_cdar(outpath, os.path.splitext(outpath)[0], True)
                
    os.close(fd)
    return cdar

def import_cdar(indir, orgpath, outpath="OUT.DAR"):
    pass

def debug():
    export_cdar(r"D:\Make\Reverse\KiniroNoCorda_psp\test2\DATA.BIN", r"D:\Make\Reverse\KiniroNoCorda_psp\test2\DATA")
    pass

def main():
    if len(sys.argv) < 3:
        print("cdar e darpath [outdir]")
        print("cdar i indir orgdarpath [outpath]")
        return
    if sys.argv[1].lower() == 'e':
        outdir = sys.argv[3] if len(sys.argv) > 3 else "OUT"
        export_cdar(sys.argv[2], outdir)
    elif sys.argv[1].lower() == 'i':
        outdir = sys.argv[4] if len(sys.argv) > 4 else "OUT.DAR"
        import_cdar(sys.argv[2], sys.argv[3], outdir)
    else: raise NotImplementedError(
        f"unknow type {sys.argv[1]}")

if __name__ == "__main__":
    #debug()
    main()
    pass