"""
majiro engine, decrypt mjo file,  MajiroObjX1.000 -> MajiroObjV1.000
  v0.1, developed by devseed

tested game: 
  そらいろ (ねこねこソフト) v1.1

See also,  
https://github.com/AtomCrafty/MajiroTools/wiki/Format%3A-Mjo-script
https://github.com/AtomCrafty/MajiroTools/wiki/Method:-XOR-cipher

"""

import sys
import struct
from typing import List

# util functions
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
    
# majiro functions
class mjoheader_t(struct_t):
    def __init__(self, data=None, cur=0) -> None:
        self.magic = b'MajiroObjV1.000\0'
        self.main_offset, self.line_count, self.func_count = [0] * 3 
        super().__init__(data, cur, fmt='<16s3I', 
            names=['magic', 'main_offset', 'line_count', 'func_count'])
        
class mjofunc_t(struct_t):
    def __init__(self, data=None, cur=0, *, fmt=None, names=None) -> None:
        self.hash, self.offset = [0]*2
        super().__init__(data, cur, fmt="<2I", names=['hash', 'offset'])

class Mjo:
    @classmethod
    def crc32table(cls, idx):
        """
        :param index: 0~255
        """ 

        POLY = 0xEDB88320
        v = idx & 0xffffffff
        for _ in range(0, 8):
            if v & 0x1 != 0: v = (v >> 1) ^ POLY
            else: v >>= 1
        return v

    def __init__(self, data=None) -> None:
        self.m_header = mjoheader_t()
        self.m_funcs: List[mjofunc_t] = []
        self.m_names: List[str] = []
        self.m_codesize, self.m_codeoffset = [0]*2
        if data: self.parse(data)

    def parse(self, data: bytes):
        self.m_data = data
        self.m_header = mjoheader_t(data)
        cur = self.m_header.size
        for _ in range(self.m_header.func_count):
            func = mjofunc_t(data, cur)
            self.m_funcs.append(func)
            cur += func.size
        self.m_codesize, = struct.unpack_from("<I", data, cur)
        self.m_codeoffset = cur + 4

    def decrypt(self, keyoffset = 0):
        if self.m_header.magic.find(b'MajiroObjV')!=-1:
            print("already decrypted!")
            return
        
        CRC32_TABLE = [Mjo.crc32table(i) for i in range(256)]
        XOR_TABLE = [0] * 4 * len(CRC32_TABLE)
        for i in range(len(CRC32_TABLE)):
            for j in range(4):
                XOR_TABLE[4*i+j] = (CRC32_TABLE[i] >> j*8) & 0xff 

        offset = self.m_codeoffset
        for i in range(self.m_codesize):
            self.m_data[offset+i] ^= XOR_TABLE[(keyoffset + i) % len(XOR_TABLE)]
        self.m_header.magic = self.m_header.magic.replace(b'X', b'V')
        self.m_data[:self.m_header.size] = self.m_header.tobytes()

def decrypt_mjo(inpath, outpath="out.mjo"):
    with open(inpath, 'rb') as fp:
        data = bytearray(fp.read())
    mjo = Mjo(data)
    mjo.decrypt()
    if outpath is not None:
        with open(outpath, 'wb') as fp:
            fp.write(mjo.m_data)
    return mjo.m_data

def debug():
    decrypt_mjo("build/workflow/2.pre/data_mjo/現代花子共通.mjo")

def main():
    if len(sys.argv) < 3:
        print("majiro_mjo d inpath [outpath]")
        return
    if sys.argv[1].lower() == 'd':
        outpath = sys.argv[3] if len(sys.argv) > 3 else "out.mjo"
        decrypt_mjo(sys.argv[2], outpath)
    else: raise ValueError(f"unknow format {sys.argv[1]}")

if __name__ == '__main__':
    # debug()
    main()
    pass