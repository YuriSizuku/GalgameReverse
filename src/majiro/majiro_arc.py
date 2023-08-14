"""
majiro engine, arc export or build
  v0.1, developed by devseed

tested game: 
  そらいろ (ねこねこソフト) v1.1

See also,  
https://github.com/AtomCrafty/MajiroTools/wiki/Format%3A-Arc-archive

"""

import os
import sys
import mmap
import struct
from io import BytesIO
from collections import namedtuple
from typing import List

# util function
class struct_t(struct.Struct):
    """
    base class for pack or unpack struct, 
    _ for meta info, __ for internal info
    """
    
    def __init__(self, data=None, cur=0, *, fmt=None, names=None) -> None:
        """"
        _meta_fmt: struct format
        _meta_names: method names 
        """

        if not hasattr(self, "_meta_names"): self._meta_names = []
        if not hasattr(self, "_meta_fmt"): self._meta_fmt = ""
        if names: self._meta_names = names
        if fmt: self._meta_fmt = fmt
        super().__init__(self._meta_fmt)
        if data: self.frombytes(data, cur)

    def cppinherit(self, fmt, names):
        if not hasattr(self, "_meta_names"): self._meta_names = names
        else: self._meta_names =  names + self._meta_names
        if not hasattr(self, "_meta_fmt"): self._meta_fmt = fmt
        else: self._meta_fmt += fmt.lstrip('<').lstrip('>')
        
    def frombytes(self, data, cur=0, *, fmt=None) -> None:
        if fmt: vals = struct.unpack_from(fmt, data, cur)
        else: vals = self.unpack_from(data, cur)
        names = self._meta_names
        for i, val in enumerate(vals):
            if i >= len(names): break
            setattr(self, names[i], val)
        self._data = data
    
    def tobytes(self, *, fmt=None) -> bytes:
        vals = []
        names = self._meta_names
        for name in names:
            vals.append(getattr(self, name))
        if fmt: _data = struct.pack(fmt, *vals)
        else: _data = self.pack(*vals)
        return _data

# majiro function
class archeader_t(struct_t):
    def __init__(self, data=None, cur=0) -> None:
        self.magic = b'MajiroArcV3.000\0'
        self.count, self.name_offset, self.data_offset = [0] * 3 
        super().__init__(data, cur, fmt="<16s3I", 
            names=['magic', 'count', 'name_offset', 'data_offset'])

class arcentry_t(struct_t):
    def __init__(self, data=None, cur=0, *, fmt=None, names=None) -> None:
        self.hash, self.offset, self.length = [0] * 3
        self._addr = cur
        super().__init__(data, cur, fmt=fmt, names=names)

class arcentryv3_t(arcentry_t):
    def __init__(self, data=None, cur=0) -> None:
        self.cppinherit("<QII", ['hash', 'offset', 'length'])
        super().__init__(data, cur)

    def crc(self, data, init=0) -> int:
        """
        majiro non-standard crc64
        refer from https://github.com/AtomCrafty/MajiroTools/wiki/Method%3A-CRC-hash
        """
        
        def _calc64(idx):
            POLY = 0x42F0E1EBA9EA3693
            v = idx
            for _ in range(0, 8):
                if (v & 0x1) != 0:  v = (v >> 1) ^ POLY;
                else: v >>= 1 #  Check LSB
            return v

        v = (~init) & 0xffffffffffffffff
        for d in data:
            v = (v >> 8) ^ _calc64((v ^ d)&0xff)

        return ~v & 0xffffffffffffffff

class Arc:
    def __init__(self, data=None, encoding="sjis") -> None:
        self.m_header = archeader_t()
        self.m_entries: List[arcentry_t] = []
        self.m_names: List[str] = []
        self._encoding = encoding
        if data: self.parse(data)

    def parse(self, data: bytes):
        self.m_data = data
        self.m_header = archeader_t(data)
        count = self.m_header.count
        entry_addr = self.m_header.size
        if self.m_header.magic == b'MajiroArcV3.000\0':
            for i in range(count):
                entry = arcentryv3_t(data, entry_addr + 16*i)
                self.m_entries.append(entry)
        else:
            raise ValueError(f"{self.m_header.magic} format not suppport")
        cur = self.m_header.name_offset
        for i in range(count):
            end = cur
            while data[end]: end += 1
            name = bytes(data[cur: end]).decode(self._encoding)
            self.m_names.append(name)
            cur = end + 1

    def export(self, outdir):
        for i, (name, entry) in enumerate(zip(self.m_names, self.m_entries)):
            print(f"{i+1}/{len(self.m_names)} export {name}, "
                  f"hash={entry.hash:x}, offset={entry.offset:X}, length={entry.length:x}")
            with open(os.path.join(outdir, name), 'wb') as fp:
                fp.write(self.m_data[entry.offset: entry.offset + entry.length])

    def load(self, inpathes, names=None, version=3): 
        if version not in [3]: 
            raise ValueError(f"unsupported arc version {version}!")
        if names: self.m_names = names
        else: self.m_names = [os.path.basename(path) for path in inpathes]
        assert(len(inpathes) == len(self.m_names))
        if version==3: 
            self.m_header.magic = b'MajiroArcV3.000\0'
            entry_size = arcentryv3_t().size
            crc = arcentryv3_t().crc
            arcentry = arcentryv3_t

        # prepare names
        nameinfo_t = namedtuple("nameinfo_t", ["idx", "data", "hash"])
        nameinfos = [nameinfo_t(i, name.encode(self._encoding),
            crc(name.encode(self._encoding))) for i, name in enumerate(names)]
        nameinfos.sort(key=lambda x: x.hash) # must sort for index
        bufio_name = BytesIO()
        for nameinfo in nameinfos:
            bufio_name.write(nameinfo.data + b'\0')

        # update header
        count = len(inpathes)
        self.m_header.count = count
        self.m_header.name_offset = self.m_header.size + count*entry_size
        self.m_header.data_offset =  self.m_header.name_offset + bufio_name.tell()
        shift = self.m_header.data_offset

        # prepare content and update entry, must sort by hash
        bufio_content = BytesIO()
        for i, nameinfo in enumerate(nameinfos):
            idx = nameinfo.idx
            entry = arcentry()
            with open(inpathes[idx], 'rb') as fp:
                tmpdata = fp.read()
                entry.length = len(tmpdata)
                entry.offset = shift + bufio_content.tell()
                entry.hash = nameinfo.hash
                self.m_entries.append(entry)
                bufio_content.write(tmpdata)
                print(f"{i+1}/{len(self.m_names)} load {self.m_names[idx]}, "
                    f"hash={entry.hash:x}, offset={entry.offset:X}, length={entry.length:x}")

        # merge buffer
        bufio = BytesIO()
        bufio.write(self.m_header.tobytes())
        for entry in self.m_entries:
            bufio.write(entry.tobytes())
        assert(bufio.tell()==self.m_header.name_offset)
        bufio.write(bufio_name.getbuffer())
        assert(bufio.tell()==self.m_header.data_offset)
        bufio.write(bufio_content.getbuffer())
        self.m_data = bufio.getbuffer()

def export_arc(inpath, outdir="out"):
    fd = os.open(inpath, os.O_RDWR)
    m = mmap.mmap(fd, 0)
    majiroarc = Arc(m)
    majiroarc.export(outdir)
    os.close(fd)

def build_arc(indir, outpath="out.arc"):
    names = os.listdir(indir)
    inpaths = [os.path.join(indir, name) for name in names]
    majiroarc = Arc()
    majiroarc.load(inpaths, names)
    with open(outpath, 'wb') as fp:
        fp.write(majiroarc.m_data)

def debug():
    export_arc("build/intermediate/zorigin/scenario.arc", "build/intermediate/zorigin/scenario")
    build_arc("build/intermediate/zorigin/scenario", "build/intermediate/zorigin/scenario2.arc")
    pass

def main():
    if len(sys.argv) < 3:
        print("majiro_arc e inpath [outdir]")
        print("majiro_arc b indir  [outpath]")
        return
    if sys.argv[1].lower() == 'e':
        outdir = sys.argv[3] if len(sys.argv) > 3 else "out"
        export_arc(sys.argv[2], outdir)
    elif sys.argv[1].lower() == 'b':
        outpath = sys.argv[3] if len(sys.argv) > 3 else "out.arc"
        build_arc(sys.argv[2], outpath)
    else: raise ValueError(f"unknow format {sys.argv[1]}")

if __name__ == '__main__':
    # debug()
    main()
    pass