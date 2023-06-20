
"""
    This is the script for flowers4 psv, pak extract, insert.
    The font.pak is aligned by 0x800, script.pak is by 0x4
    v0.1, developed by devseed
"""

import struct
import mmap
import os
import sys
from io import BytesIO

class Pak:
    def __init__(self, path=""):
        self.data = None
        # pak structure
        self.itemnum = 0x0 # dword
        self.itemidx = [] # (start offset, length)
        self.itemname = [] # most of 10byte strings end with \x00,
        self.items = [] #ITEM_STRUCT
        
        self.hasname = True
        self.align = 0x800
        self.cur_padding = 1
        self.idxstart = 0x28
        self.namefstr = "{num:04}"

        if path != "" :
            if path.find('FONT') != -1: 
                self.align = 0x800
                self.cur_padding = 1
            elif path.find('OTHCG') != -1:
                self.align = 0x800
                self.cur_padding = 0xd
            elif path.find('SCRIPT') != -1 : 
                self.align = 0x4
                self.cur_padding = 0
            self.read_pak(path)

    def read_pak(self, path):
        f = os.open(path, os.O_BINARY)
        data = mmap.mmap(f, 0, access=mmap.ACCESS_READ)
        self.data = data
        self.itemnum = struct.unpack('I', data[0x4:0x8])[0]
        if int.from_bytes(data[0x28:0x28+0x4], 'little') == 0:
            self.idxstart = 0x28 + 0x4
        cur = self.idxstart
        for i in range(self.itemnum):
            self.itemidx.append(struct.unpack('II', data[cur:cur+0x8]))
            cur += 0x8
        if data[cur] != 0:
            for i in range(self.itemnum):
                end = data.find(b'\x00', cur)
                try:
                    name = data[cur: end].decode('sjis')
                except UnicodeDecodeError:
                    self.hasname = False
                    break
                if name not in self.itemname:
                    self.itemname.append(name)
                else:                    
                    self.hasname = False
                    break
                cur = end + 1
        else: self.hasname = False

        if self.hasname is False:            
            self.align = 0x800
            self.itemname=[self.namefstr.format(num=i) for i in range(self.itemnum)]

    def extract(self, outdir=""):
        print("%d files to extract..." %self.itemnum)
        for i in range(self.itemnum):
            with open(os.path.join(outdir, self.itemname[i]), 'wb') as f:
                f.write(self.data[self.itemidx[i][0] * self.align : self.itemidx[i][0] * self.align + self.itemidx[i][1]])
                print(self.itemidx[i][0], self.itemidx[i][0] + self.itemidx[i][1], self.itemname[i], "extracted! ")

    def repack(self, indir, outpath):
        files = os.listdir(indir)
        data = BytesIO()
        cur = self.itemidx[0][0] * 4
        align = self.align
        for i, name in enumerate(self.itemname):
            if name in files:
                with open(os.path.join(indir, name), 'rb') as fp:
                    _data = fp.read()
                    data.write(_data)
                if len(_data) % align != 0:
                    data.write(b'\x00' * (align -len(_data) % align))
                    size = len(_data) + align - len(_data) % align
                else: size = len(_data)
                print("%s (%x, %x) -> (%x, %x)" % (name, self.itemidx[i][0], self.itemidx[i][1], cur//align+self.cur_padding, len(_data)))
                self.itemidx[i] = (cur//align+self.cur_padding, len(_data))
                
            else:
                start = self.itemidx[i][0] * align
                end = start + self.itemidx[i][1]
                data.write(self.data[start:end])
                if self.itemidx[i][1] % align != 0:
                    data.write(b'\x00' * (align -self.itemidx[i][1] % align))
                    size =self.itemidx[i][1] + align - self.itemidx[i][1] % align
                else: size = self.itemidx[i][1]
                self.itemidx[i] = (cur//align+self.cur_padding, self.itemidx[i][1])
            cur += size
                
        with open(outpath, 'wb') as fp:
            fp.write(self.data[0:4])
            fp.write(int.to_bytes(self.itemnum, 4, 'little'))
            fp.write(self.data[0x8:self.idxstart])
            for i in range(self.itemnum):
                fp.write(struct.pack('<II', self.itemidx[i][0], self.itemidx[i][1]))
            if self.hasname:
                for i in range(self.itemnum):
                    fp.write(self.itemname[i].encode('sjis') + b"\x00")
            cur = fp.tell()
            if cur != self.itemidx[0][0] * self.align:
                fp.write(b'\x00' * (self.itemidx[0][0]*self.align - cur))
            fp.write(data.getbuffer())

class ITEM_STRUCT:
    pass

def extract_pak(pakpath, outdir):
    pak = Pak(pakpath)
    pak.extract(outdir)
    print('extract pak finished!')

def insert_pak(orgpakpath, indir, outpath):
    pak = Pak(orgpakpath)
    pak.repack(indir, outpath)
    print('insert pak finished!')

def debug():
    extract_pak(r"D:\MAKE\Reverse\flowers\flowers4\CG\EVENTCG.PAK", r"D:\MAKE\Reverse\flowers\flowers4\CG\EVENTCG_org")
    insert_pak(r"D:\MAKE\Reverse\flowers\flowers4\CG\EVENTCG.PAK", r"D:\MAKE\Reverse\flowers\flowers4\CG\EVENTCG_org", r"D:\MAKE\Reverse\flowers\flowers4\CG\EVENTCG_rebuild.PAK")

def main():
    if len(sys.argv) < 3:
        print("flowers_pak e pakpath [outdir]")
        print("flowers_pak i orgpakpath indir [outpath]")
        return
    if sys.argv[1].lower() == 'e':
        pakpath = sys.argv[2]
        if len(sys.argv) < 4: outdir = os.path.dirname(pakpath)
        else: outdir = sys.argv[3]
        extract_pak(pakpath, outdir)
    elif sys.argv[1].lower() == 'i':
        orgpakpath = sys.argv[2]
        indir = sys.argv[3]
        if len(sys.argv) < 5: outpath = os.path.splitext(orgpakpath)[0] + "_rebuild.pak"
        else: outpath = sys.argv[4]
        insert_pak(orgpakpath, indir, outpath)

if __name__ == "__main__":
    #debug()
    main()