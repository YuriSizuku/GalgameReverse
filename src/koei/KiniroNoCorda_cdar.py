"""
for parsing cdvdar (type v2) structure of koei, tested by 金色のコルダ
  v0.1, developed by devseed
"""

import os
import sys
import zlib
import json
import mmap
import struct
from io import BytesIO
from typing import Dict, List, Union

class cdarnode_t(struct.Struct):
    def __init__(self, data: bytes, offset: int, recursive=True):
        super().__init__("<IB3B2I")
        self.frombytes(data, offset, recursive)

    def frombytes(self, data: bytes, offset: int, recursive=True):
        self.data = data
        self.indexoffset = offset
        (self.nameoffset, self.datatype, 
            d1, d2, d3,
            self.dataoffset, self.datasize) = \
            self.unpack_from(data[offset:])
        self.datazsize = d1 + (d2<<8) + (d3<<16)
        self.subtree = None
        nstart = self.nameoffset
        nend = self.data.find(b'\0', nstart)
        self.name = self.data[nstart : nend].decode()

        if recursive:
            if self.datatype == 1:
                self.subtree = cdartree_t(
                    self.data, self.dataoffset)
            
class cdartree_t(struct.Struct):
    def __init__(self, data: bytes, offset: int):
        super().__init__("<4I")
        self.frombytes(data, offset)

    def frombytes(self, data, offset):
        self.data = data
        self.indexoffset = offset
        (self.count, _, _ ,_) = self.unpack_from(data[offset:])
        self.nodes: List[cdarnode_t] = []
        for i in range(self.count):
            self.nodes.append(cdarnode_t(
                self.data, offset + self.size + i*0x10))
            
class cdar_t(struct.Struct):
    def __init__(self, data: bytes):
        super().__init__("<4I")
        self.frombytes(data)

    def frombytes(self, data: bytes):
        self.data = data
        (self.magic, self.version, 
        self.hsize, self.hash) = \
        self.unpack_from(data)
        self.subtree = cdartree_t(self.data, self.size)

    def flatten(self) -> Dict[str, cdarnode_t]:
        objmap: Dict[str, cdarnode_t] = dict()
        _nodestack: List[Union[cdarnode_t, None]] = []
        _nodestack.extend(self.subtree.nodes)
        _pathstack: List[dir] = ['']

        while len(_nodestack) > 0:
            t: cdarnode_t = _nodestack.pop()
            if t is None: # to seperate folder
                _pathstack.pop()
                continue

            if t.subtree is None:
                path = "/".join(_pathstack) + "/" + t.name
                objmap.update({path.lstrip('/'): t})
            else:
                _pathstack.append(t.name)
                _nodestack.append(None)
                _nodestack.extend(t.subtree.nodes)

        return objmap

def export_cdar(inpath, outdir="./OUT"):
    fd = os.open(inpath, os.O_RDWR)
    data = mmap.mmap(fd, 0)

    print("trying to parse the cdvdar tree, this may take some time...")
    cdar = cdar_t(data)
    objmap = cdar.flatten()

    if outdir!="":
        cdvdarlist = []
        for k, v in objmap.items():
            node = {'path': k, 
                'indexoffset': v.indexoffset, 
                'datatype': v.datatype,
                'dataoffset': v.dataoffset, 
                'datasize': v.datasize, 
                'datazsize': v.datazsize}
            cdvdarlist.append(node)
            
            path = os.path.join(outdir, k)
            dir = os.path.dirname(path)
            if not os.path.exists(dir):
                os.makedirs(dir)

            with open(path, 'wb') as fp: 
                if v.datatype & 2:
                    fp.write(zlib.decompress(
                        data[v.dataoffset: v.dataoffset + v.datazsize]))
                    print(node, "zlib decompress dumped!")
                else: 
                    fp.write(data[v.dataoffset: 
                        v.dataoffset + v.datasize])
                    print(node, "raw dumped!")

        name = os.path.basename(inpath)
        path = os.path.join(outdir, name + '.json')
        with open(path, 'w') as fp:
            json.dump(cdvdarlist, fp, indent=2)

    os.close(fd)
    return cdar, objmap

def import_cdar(indir, orgpath, outpath="OUT.DAR"):
    """
    this is to append files to cdvdar structure,
    """
    with open(orgpath, 'rb') as fp:
        data = bytearray(fp.read())
    
    cdarlist = None
    targetlist = []

    # search for replaced files
    for root, dirs, files in os.walk(indir):
        basedir = os.path.relpath(root, indir)
        for file in files:
            if os.path.splitext(file)[0] == os.path.basename(orgpath):
                with open(os.path.join(root, file), 'r') as fp:
                    cdarlist = json.load(fp)
            else:
                path = os.path.join(basedir, file)
                targetlist.append(path.replace('\\', '/').lstrip('.').lstrip('/'))

    # parse origin dar file
    if cdarlist is None:
        print("trying to parse the cdvdar tree, this may take some time...")
        cdar = cdar_t(data)
        objmap = cdar.flatten()
        cdarlist = []
        for k, v in objmap.items():
            node = {'path': k, 
                'indexoffset': v.indexoffset, 
                'datatype': v.datatype,
                'dataoffset': v.dataoffset, 
                'datasize': v.datasize, 
                'datazsize': v.datazsize}
            cdarlist.append(node)

    # append the new file into cdvdar, not worked
    align = 0x800
    bufio = BytesIO()
    end = len(data)
    if end % align:
        n = align-end%align
        bufio.write(b'\x00' * n) 
    for t in cdarlist:
        if t['path'] in targetlist:
            dataoffset = end + bufio.tell()
            if dataoffset % align:
                n = align - dataoffset % align
                dataoffset += n
                bufio.write(b'\x00' * n) 
            with open(os.path.join(indir, t['path']), 'rb') as fp:
                _data = fp.read()
                datasize = len(_data)
                bufio.write(zlib.compress(_data))
                datazsize = end + bufio.tell() - dataoffset
            d = 0x2 + (datazsize<<8)
            data[t['indexoffset'] + 0X4 : t['indexoffset'] + 0x10] = \
                struct.pack("<3I", d, dataoffset, datasize)
            print(f"append {t['path']}, index at 0x{t['indexoffset']:x}, to 0x{dataoffset:x}, size 0x{datasize:x}")

    if outpath!="":
        with open(outpath, 'wb') as fp:
            fp.write(data)
            fp.write(bufio.getbuffer())

    return data

def import_cdar2(indir, orgpath, outpath="OUT.DAR"):
    """
    this is to rebuild the cdvdar structure,
    now it has some bugs
    """
    with open(orgpath, 'rb') as fp:
        data = bytearray(fp.read())
    
    cdarlist = None
    targetlist = []

    # search for replaced files
    for root, dirs, files in os.walk(indir):
        basedir = os.path.relpath(root, indir)
        for file in files:
            if os.path.splitext(file)[0] == os.path.basename(orgpath):
                with open(os.path.join(root, file), 'r') as fp:
                    cdarlist = json.load(fp)
            else:
                path = os.path.join(basedir, file)
                targetlist.append(path.replace('\\', '/').lstrip('.').lstrip('/'))

    # parse origin dar file
    if cdarlist is None:
        print("trying to parse the cdvdar tree, this may take some time...")
        cdar = cdar_t(data)
        objmap = cdar.flatten()
        cdarlist = []
        for k, v in objmap.items():
            node = {'path': k, 
                'indexoffset': v.indexoffset, 
                'datatype': v.datatype,
                'dataoffset': v.dataoffset, 
                'datasize': v.datasize, 
                'datazsize': v.datazsize}
            cdarlist.append(node)

    # insert file into dar
    cdarlist.sort(key=lambda x: x['dataoffset'])
    for t in cdarlist:
        if t['path'] in targetlist:
            with open(os.path.join(indir, t['path']), 'rb') as fp:
                _data = fp.read()
                t['content'] = zlib.compress(_data)
                t['datatype'] = 0x2
                t['datasize'] = len(_data)
                t['datazsize'] = len(t['content'])
            print(f"insert {t['path']}, index at 0x{t['indexoffset']:x}, size 0x{t['datasize']:x}")
        else: 
            size = t['datazsize'] if t['datatype'] & 0x2 else t['datasize']
            t['content'] = data[t['dataoffset']: t['dataoffset'] + size]

    # fix the index
    align = 0x800
    indexend = cdarlist[0]['dataoffset']
    bufio = BytesIO()
    for t in cdarlist:
        dataoffset = indexend + bufio.tell()
        if dataoffset % align:
            n = align - dataoffset % align
            dataoffset += n
            bufio.write(b'\x00' * n) 
        bufio.write(t['content'])
        d = t['datatype'] + (t['datazsize']<<8)
        data[t['indexoffset'] + 0X4 : t['indexoffset'] + 0x10] = \
            struct.pack("3I", d, dataoffset, t['datasize'])
        t['dataoffset'] = dataoffset

    if outpath!="":
        with open(outpath, 'wb') as fp:
            fp.write(data[:indexend])
            fp.write(bufio.getbuffer())

    return data

def debug():
    import_cdar("./build/intermediate/cdvdar_rebuild/", "./build/intermediate/CDVDAR.DAR")
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
    # debug()
    main()
    pass