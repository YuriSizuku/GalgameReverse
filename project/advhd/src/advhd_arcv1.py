"""
export or build arc v1 for willplus advhd 
tested in AyakashiGohan (v1.0.1.0)
    v0.1, developed by devseed
"""

import os
import sys
import mmap
import struct
from io import BytesIO
from typing import List, Tuple

class advhdv1_extentry_t(struct.Struct):
    def __init__(self, data=None, offset=0):
        super().__init__('<4s2I')
        if data!=None: self.frombytes(data, offset)

    def frombytes(self, data, offset=0):
        (self.name, self.nfile, self.offset) \
            = self.unpack_from(data, offset)

    def tobytes(self):
        return self.pack(
            self.name, self.nfile, self.offset)

class advhdv1_fileentry_t(struct.Struct):
    def __init__(self, data=None, offset=0):
        super().__init__('<13s2I')
        if data!=None: self.frombytes(data, offset)

    def frombytes(self, data, offset=0):
        (self.name, self.fsize, self.offset) \
            = self.unpack_from(data, offset)

    def tobytes(self):
        return self.pack(
            self.name, self.fsize, self.offset)

def ror(d, n):
    n &= 7
    return (d>>n | d<<(8-n)) & 0xff

def rol(d, n):
    n &= 7
    return (d<<n | d>>(8-n)) & 0xff

def parse_arc(data: bytes) -> \
        Tuple[List[advhdv1_extentry_t], List[advhdv1_fileentry_t]]:
    
    ext_entries: List[advhdv1_extentry_t] = []
    file_entries: List[advhdv1_fileentry_t] = []

    cur = 4
    n = int.from_bytes(data[0:4], 'little', signed=False)
    for i in range(n):
        ext_entry = advhdv1_extentry_t(data, cur)
        ext_entries.append(ext_entry)
        cur += ext_entry.size
    
    for ext_entry in ext_entries:
        cur = ext_entry.offset
        for i in range(ext_entry.nfile):
            file_entry = advhdv1_fileentry_t(data, cur)
            file_entries.append(file_entry)
            cur += file_entry.size

    return ext_entries, file_entries

def export_arc(inpath, outdir="./out"):
    fd = os.open(inpath, os.O_RDONLY)
    data = mmap.mmap(fd, 0, access=mmap.ACCESS_READ)
    ext_entries, file_entries = parse_arc(data)

    if outdir != "":
        extidx = 0
        extname = ext_entries[extidx].name.decode().rstrip('\x00')
        n = ext_entries[extidx].nfile
        lasti = 0
        for i, file_entry in enumerate(file_entries):
            if i - lasti >= n:
                extidx += 1
                extname = ext_entries[extidx].name.decode().rstrip('\x00')
                n = ext_entries[extidx].nfile
                lasti = i
            outname = file_entry.name.decode().rstrip('\x00')
            outpath = os.path.join(outdir, outname + "." + extname)
            with open(outpath, 'wb') as fp:
                targetbytes = data[file_entry.offset: 
                    file_entry.offset + file_entry.fsize]
                if os.path.splitext(outpath)[1].lower() == '.wsc':
                    targetbytes = bytes(map(
                        lambda x: ror(x, 2), targetbytes))
                fp.write(targetbytes)
                print(f"write {outname}.{extname}, "
                    f"offset 0x{file_entry.offset:x}, "
                    f"size 0x{file_entry.fsize:x}")
        
    data.close()
    os.close(fd)
    return ext_entries, file_entries

def build_arc(indir, outpath="out.arc"):
    # prepare index
    ext_entry = advhdv1_extentry_t()
    file_entry = advhdv1_fileentry_t()
    ext_entries: List[advhdv1_extentry_t] = []
    file_entries: List[advhdv1_fileentry_t] = []
    fnames = os.listdir(indir)
    fnames.sort(key=lambda x: x[-4:])

    # prepare ext entry and file entry information
    extset = set()
    for fname in fnames:
        ext = os.path.splitext(fname)[1].lstrip('.')
        ext = ext.ljust(4, '\0').encode()
        if ext not in extset:
            ext_entry = advhdv1_extentry_t()
            ext_entry.name = ext
            ext_entry.nfile = 1
            ext_entries.append(ext_entry)
            extset.add(ext)
        else: ext_entries[-1].nfile += 1
    
    extidx = 0
    extentry_offset = 0x4
    fileentry_offset = extentry_offset + len(extset) * ext_entry.size
    content_offset = fileentry_offset + len(fnames) * file_entry.size
    ext_entries[extidx].offset = fileentry_offset
    cur = content_offset
    for i, fname in enumerate(fnames):
        inpath = os.path.join(indir, fname)
        name = os.path.splitext(fname)[0]
        name = name.ljust(13, '\0').encode()
        ext = os.path.splitext(fname)[1].lstrip('.')
        ext = ext.ljust(4, '\0').encode()
        if ext_entries[extidx].name != ext:
            extidx += 1
            ext_entries[extidx].offset = \
                fileentry_offset + i*file_entry.size
        file_entry = advhdv1_fileentry_t()
        file_entry.name = name
        file_entry.fsize = os.stat(inpath).st_size
        file_entry.offset = cur
        file_entries.append(file_entry)
        cur += file_entry.fsize

    # write ext entry and file entry index
    bufio = BytesIO()
    bufio.write(int.to_bytes(
        len(extset), 4, 'little', signed=False))
    for ext_entry in ext_entries:
        bufio.write(ext_entry.tobytes())
    assert(bufio.tell()==fileentry_offset)
    for file_entry in file_entries:
        bufio.write(file_entry.tobytes())
    assert(bufio.tell()==content_offset)
    
    # write file content
    extidx = 0
    lasti = 0
    for i, file_entry in enumerate(file_entries):
        name: str = file_entry.name.decode().rstrip('\0')
        if i - lasti >= ext_entries[extidx].nfile:
            lasti = i
            extidx += 1
        ext: str = ext_entries[extidx].name.decode().rstrip('\0')
        inpath = os.path.join(indir, name+'.'+ext)
        with open(inpath, 'rb') as fp:
            targetbytes = fp.read()
            if ext.lower() == 'wsc':
                targetbytes = bytes(map(
                    lambda x: rol(x, 2), targetbytes))
        bufio.write(targetbytes)
        assert(bufio.tell()== file_entry.offset + file_entry.fsize)
        print(f"read {name}.{ext}, "
                f"offset 0x{file_entry.offset:x}, "
                f"size 0x{file_entry.fsize:x}")
    
    if outpath:
        with open(outpath, 'wb') as fp:
            fp.write(bufio.getbuffer())

    return bufio.getbuffer()

def debug():
    pass

def main():
    if len(sys.argv) < 3:
        print("advhd_arcv1 e inpath [outdir]")
        print("advhd_arcv1 b indir  [outpath]")
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