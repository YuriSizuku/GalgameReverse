"""
   FNT tool for 9nine, 
   v0.1, developed by devseed

   see also,  
   https://github.com/DCNick3/shin/blob/master/shin-core/src/format/font.rs
"""

import os
import sys
import struct
import codecs
import numpy as np
import zipfile
from glob import glob
from io import BytesIO
from PIL import Image
from typing import List, Dict, Union

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

# fnt functions
class fntheader_t(struct_t):
    def __init__(self, data=None, cur=0) -> None:
        self.magic = b'FNT4'
        self.version = 1
        self.fsize = 0 # filesize
        self.distop, self.disbottom = [0] * 2 # distance between baseline and top/bottom
        super().__init__(data, cur, fmt='<4s2I2H', 
            names=['magic', 'version', 'fsize', 'distop', 'disbottom'])

class fntglphyheader_t(struct_t):
    def __init__(self, data=None, cur=0, ref_unicode=0) -> None:
        self.bearingx, self.bearingy = [0] * 2 # distance between the baseline
        self.actualw, self.actualh = [0] * 2 # actual size without padding
        self.advancew, self.unused = [0] * 2 # might not use
        self.texturew, self.textureh = [0] * 2
        self.unused1 = 0
        self.zsize = 0 # compressed size
        super().__init__(data, cur, fmt='<2b6BH', 
            names=['bearingx', 'bearingy', 'actualw', 'actualh', 'advancew', 'unused1', 'texturew', 'textureh', 'zsize'])
        self.ref_glphyaddr = cur + self.size
        self.ref_unicode = ref_unicode

class Fnt:
    @classmethod
    def lz77_encodefake(cls, data, size, cur=0, offsetbits=10) -> bytes:
        """
        fake compress method with nothing compressed
        """

        buf = BytesIO()
        for i in range(size):
            if i%8 == 0: buf.write(bytes([0x00]))
            buf.write(bytes([data[cur+i]]))
        return buf.getbuffer()
    
    @classmethod
    def lz77_encode(cls, data, size, cur=0, offsetbits=10) -> bytes:
        """
        need to find the longest match string 
        between the previous and next in sliding window
        """
        return cls.lz77_encodefake(data, size, cur, offsetbits)
    
    @classmethod
    def lz77_decode(cls, data, size, cur=0, offsetbits=10) -> bytes:
        """
        MSB  XXXXXXXX          YYYYYYYY    LSB
        val  len               backOffset
        size (16-OFFSET_BITS)  OFFSET_BITS

        index8, 8 * [val16 | val8]
        """
        
        buf = BytesIO()
        i = 0
        while i < size:
            index8 = data[cur+i]
            i += 1
            for j in range(8):
                flag = (index8 >> j) & 1
                if flag == 0: # direct byte output
                    if(i>=size): break # sometimes no other bytes in the end
                    buf.write(bytes([data[cur+i]])) 
                    i += 1
                else: # seek from output
                    backseekval = int.from_bytes(data[cur+i: cur+i+2], 'big', signed=False)
                    backoffsetmask = (1<<offsetbits) - 1
                    backlength = (backseekval >> offsetbits) + 3 # length must larger than 3
                    backoffset = (backseekval & backoffsetmask) + 1
                    for _ in range(backlength): # push char to output one by one
                        seekstart = buf.tell() - backoffset
                        buf.write(bytes([buf.getbuffer()[seekstart]]))
                    i += 2
        return buf.getbuffer()

    @classmethod
    def miplevel(cls, size, w, h):
        level = 0
        cursize = 0
        while cursize < size:
            cursize += (w//2**level)*(h//2**level)
            level += 1
        return level

    def __init__(self, data=None) -> None:
        if data: self.parse(data)
    
    def parse(self, data):
        self.m_data = data
        self.m_header = fntheader_t(data)
        self.m_unicodemap: List[int]  = 0x10000 * [0] # unicode: addr
        self.m_glphymap: Dict[int, fntglphyheader_t] = dict() # addr: header
        for i in range(0x10000):
            start = i*4 + self.m_header.size
            self.m_unicodemap[i] = int.from_bytes(data[start: start+4], 'little', signed=False)
        for unicode, addr in enumerate(self.m_unicodemap):
            if addr in self.m_glphymap: continue
            glphyheader = fntglphyheader_t(data, addr, unicode)
            self.m_glphymap.update({addr: glphyheader})

    def flush(self, data=None):
        if data: self.m_data = bytearray(data)
        else: self.m_data = bytearray(data)
        assert(self.m_header.fsize == len(self.m_data))

        self.m_data[:self.m_header.size] = self.m_header.tobytes()
        cur = self.m_header.size
        for addr in self.m_unicodemap: # flash unicode map
            self.m_data[cur: cur+4] = int.to_bytes(addr, 4, 'little', signed=False)
            cur += 4
        for (addr, glphyheader) in self.m_glphymap.items(): # flush glphy header
            size = glphyheader.size
            cur = glphyheader.ref_glphyaddr - size
            self.m_data[cur: cur + size] = glphyheader.tobytes()

    def extract(self, outpath="out") -> None:
        zipfp = None
        loglines = []
        if os.path.splitext(outpath)[1] == '.zip':
            zipfp = zipfile.ZipFile(outpath, 'w')
            logpath = os.path.splitext(outpath)[0] + '.txt'
        else:
            if not os.path.exists(outpath): os.makedirs(outpath)
            logpath = os.path.join(outpath, 'log.txt')
        for (addr, glphy_header) in self.m_glphymap.items():
            unicode = glphy_header.ref_unicode
            outname = f"{addr:06x}_{unicode:02x}"
            if zipfp: 
                imgbuf = BytesIO()
                decdata = self.extract_single(unicode, imgbuf)
                with zipfp.open(outname + ".png", "w") as fp:
                    fp.write(imgbuf.getbuffer())
            else: decdata = self.extract_single(unicode, os.path.join(outpath, outname + ".png"))
            w, h = glphy_header.texturew, glphy_header.textureh
            miplevel = self.miplevel(len(decdata), w, h)
            logstr = f"{outname},{chr(unicode)},{w},{h},{miplevel}"
            loglines.append(logstr + "\r\n")
            print(logstr)
        
        with codecs.open(logpath, 'w', 'utf8') as fp:
            fp.writelines(loglines)
        if zipfp: zipfp.close()

    def extract_single(self, unicode, outobj: Union[str, BytesIO]=None) -> np.array:
        addr = self.m_unicodemap[unicode]
        glphy_header = self.m_glphymap[addr]
        decdata = self.lz77_decode(self.m_data, glphy_header.zsize, glphy_header.ref_glphyaddr)

        # only extract the max size of image in mipmap
        w, h = glphy_header.texturew, glphy_header.textureh
        if outobj!=None:
            img = np.frombuffer(decdata[0:w*h], dtype=np.uint8).reshape([w, h]) 
            Image.fromarray(img).save(outobj, format='png')
        return decdata

    def insert(self, inpath, outpath="out.fnt"):
        raise NotImplementedError()

    def append(self, inpath, outpath="out.fnt", miplevel=4):
        zipfp = None
        buf = BytesIO()
        if os.path.splitext(inpath)[1] == '.zip':
            zipfp = zipfile.ZipFile(inpath, 'r')
            files = [x.filename for x in zipfp.filelist]
        else:
            files = glob(os.path.join(inpath, "*.png"))

        for file in files:
            # load info from name
            name = os.path.splitext(file)[0]
            addr = int(name.split('_')[0], 16)
            unicode = int(name.split('_')[1], 16)

            # loadpng
            if zipfp: 
                with zipfp.open(file, 'r') as fp:
                    imgpil = Image.open(fp)
            else: imgpil = Image.open(os.path.join(inpath, file))
            h, w = imgpil.size

            # adjust unicodemap and glphymap
            flag_existglphy = False
            self.m_unicodemap[unicode] = len(self.m_data) + buf.tell()
            if addr!=0 and addr in self.m_glphymap:
                glphyheader = self.m_glphymap[addr]
                flag_existglphy = True
            else: # not sure the proper value, need test
                glphyheader = fntglphyheader_t()
                glphyheader.ref_unicode = unicode
                glphyheader.actualw = w
                glphyheader.actualh = h
                glphyheader.advancew = w
            glphyheader.textureh,  glphyheader.texturew = h, w
            glphyheader.ref_glphyaddr = len(self.m_data) + buf.tell() + glphyheader.size
            if flag_existglphy: self.m_glphymap.pop(addr)
            self.m_glphymap.update({glphyheader.ref_glphyaddr: glphyheader})
            
            # leave space and make mipmap 
            buf.write(glphyheader.size * b'\x00')
            curw, curh = w, h
            zsize = 0
            for _ in range(miplevel): # just assume all use miplevel 4
                img = np.array(imgpil.resize((curw, curh)))
                imgbytes = img.tobytes()
                encbytes = self.lz77_encode(imgbytes, len(imgbytes))
                zsize += len(encbytes)
                buf.write(encbytes)
                curw //= 2
                curh //= 2
            print(f"append {chr(unicode)}, {file}, {w}x{h}, addr={glphyheader.ref_glphyaddr:06x}, zsize={zsize:04x}")
            glphyheader.zsize = zsize

        if zipfp: zipfp.close()

        fullbuf = self.m_data + buf.getbuffer()
        self.m_header.fsize = len(fullbuf)
        self.flush(fullbuf)
        if outpath!="":
            with open(outpath, 'wb') as fp:
                fp.write(self.m_data)

def extract_fnt(fntpath, unicode=None, outpath="out.zip"):
    with open(fntpath, 'rb') as fp:
        data = fp.read()
    fnt = Fnt(data)
    if unicode: fnt.extract_single(unicode, outpath)
    else: fnt.extract(outpath)

def append_fnt(orgfntpath, inpath, outpath="out.fnt"):
    with open(orgfntpath, 'rb') as fp:
        data = fp.read()
    fnt = Fnt(data)
    fnt.append(inpath, outpath)

def insert_fnt(orgfntpath, inpath, outpath="out.fnt"):
    with open(orgfntpath, 'rb') as fp:
        data = fp.read()
    fnt = Fnt(data)
    fnt.insert(inpath, outpath)

def debug():
    def test_lz77(data):
        orgbytes = data
        encbytes = Fnt.lz77_encodefake(orgbytes,  len(orgbytes))
        decbytes = Fnt.lz77_decode(encbytes, len(encbytes))
        assert(orgbytes==decbytes)

    def test_fntextract(inpath, outpath):
        with open(inpath, 'rb') as fp:
            data = fp.read()
        fnt = Fnt(data)
        fnt.extract(outpath)

    def test_fntappend(orgfntpath, inpath, outpath):
        with open(orgfntpath, 'rb') as fp:
            data = fp.read()
        fnt = Fnt(data)
        fnt.append(inpath, outpath)

    test_lz77(b"12345678000222333")
    # test_fntextract(r"font_00.fnt", "font_00.zip")
    test_fntappend(r"font_00.fnt", "font_00.zip", "font_00_rebuild.fnt")

def main():
    if len(sys.argv) < 3:
        print("9nine_fnt e fntpath [outdir|outzip] // extract all glhpys to folder or zip file")
        print("9nine_fnt e[unicode] fntpath [outpath] // extract glphy with unicode")
        print("9nine_fnt i orgfntpath indir|inzip [outpath] // insert glphys in folder or zip file, name as a addr_unicode")
        print("9nine_fnt a orgfntpath indir|inzip [outpath] // append glphys in folder or zip file to end")
        return
    
    arg1 = sys.argv[1].lower()
    if arg1[0] == 'e':
        fntpath = sys.argv[2]
        outpath = sys.argv[3] if len(sys.argv) > 3 else "out"
        if len(arg1) == 1: unicode = None
        else: unicode = int(arg1[1:])
        extract_fnt(fntpath, unicode, outpath)
    elif arg1[0] == 'a' or arg1[0] == 'i':
        orgfntpath = sys.argv[2]
        inpath = sys.argv[3]
        outpath = sys.argv[4] if len(sys.argv) > 4 else "out.fnt"
        if arg1[0] == 'a': append_fnt(orgfntpath, inpath, outpath)
        elif arg1[0] == 'i': insert_fnt(orgfntpath, inpath, outpath)
    else: raise ValueError(f"option {sys.argv[1]} not supported")

if __name__ == "__main__":
    # debug()
    main()
    pass