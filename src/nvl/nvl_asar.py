# -*- coding: utf-8 -*-

"""
This is for decrypting asar file made by nvl cloud,
v0.2, developed by devseed

Tested game: OurEndOfTheWorld
"""

import os
import sys
import mmap
import json
import numpy as np
from io import BytesIO
from typing import List

class nvlasar_entry_t:
    def __init__(self, curdir, name, size, offset, hashstr) -> None:
        self.curdir: str = curdir
        self.name: str = name
        self.size: int = size 
        self.offset: int = offset
        self.hashstr: str = hashstr
        pass

def decrypt_nvlasar(data: bytes, hash_data: bytes, hash_offset: int, 
        bufio: BytesIO=None) -> BytesIO:

    if bufio is None:
        bufio = BytesIO(data)

    for i in range(len(data)):
        bufio.write(int.to_bytes(data[i] ^ hash_data[hash_offset], 1, 'little'))
        hash_offset += 1
        hash_offset %= len(hash_data)

    return bufio

def decrypt_nvlasar_batch(data: bytes, hash_data: bytes, hash_offset: int, 
        bufio: BytesIO=None) -> BytesIO:
    """
    optimized version by numpy buffer
    """
    if bufio is None:
        bufio = BytesIO(data)

    nbatch = 100
    hashbuf = np.zeros(len(hash_data)*nbatch, dtype=np.uint8)
    databuf = np.zeros(hashbuf.nbytes, dtype=np.uint8)
    hash_data2 = hash_data[hash_offset:] + hash_data[:hash_offset]
    
    for i in range(nbatch):
        hashbuf[i*len(hash_data): (i+1)*len(hash_data)] = np.frombuffer(hash_data2, dtype=np.uint8)

    batchend = len(data) - len(data)%databuf.nbytes
    for offset in range(0, batchend, databuf.nbytes):
        databuf =np.frombuffer(data[offset:offset+databuf.nbytes], dtype=np.uint8) ^ hashbuf
        bufio.write(databuf.tobytes())
    
    hash_offset = (hash_offset + batchend) % len(hash_data)
    for offset in range(batchend, len(data)):
        bufio.write(int.to_bytes(data[offset] ^ hash_data[hash_offset], 1, 'little'))
        hash_offset += 1
        if hash_offset >= len(hash_data): hash_offset=0

    return bufio

def export_nvlasar(inpath, outdir):

    fd = os.open(inpath, os.O_RDWR)
    m = mmap.mmap(fd, 0)

    # decrypt nvl asar index
    print("decrypting nvl asar index ...")
    index_size = int.from_bytes(m[4:8], 'little', signed=False) - 8
    index_data = decrypt_nvlasar_batch(m[0x10:0x10+index_size], m[4:8], 0).getbuffer()
    index_data = bytes(index_data)
    index_end = index_data.rfind(b'\0')
    index_json = json.loads(index_data[:index_end].decode())
    with open(os.path.join(outdir, "nvlasar_index.json"), "w") as fp:
        json.dump(index_json, fp, indent=2)

    # parse nvl asar index
    print("parsing nvl asar content ...")
    filestack = [{"obj": index_json, "objdir": outdir}]
    nvlasar_entries: List[nvlasar_entry_t] = []
    while len(filestack) > 0:
        _t = filestack.pop()
        obj = _t["obj"]
        objdir = _t["objdir"]
        if "files" in obj:
            for k, v in obj["files"].items():
                name = k
                path = os.path.join(objdir, name)
                if "files" in v:
                    filestack.append({"obj": v, "objdir": path})
                else:
                    nvlasar_entries.append(nvlasar_entry_t(
                        objdir, name,  int(v['size']), int(v["offset"]), v["hash"]))

    # decrypt nvl asar content
    content_start = index_size + 0x10
    for i, entry in enumerate(nvlasar_entries):
        entry_path = os.path.join(entry.curdir, entry.name)
        print(f"{i+1}/{len(nvlasar_entries)} {entry_path} "
            f"size={entry.size:x} offset={entry.offset:x} hash={entry.hashstr}")
        path = os.path.join(outdir, entry.curdir)
        if not os.path.exists(path): os.makedirs(path)
        path = os.path.join(path, entry.name)
        with open(path, "wb") as fp:
            start = content_start + entry.offset
            hashdata = entry.hashstr.encode() + \
                int.to_bytes(entry.size, 4, 'little', signed=False)
            decrypt_nvlasar_batch(m[start: start + entry.size], 
                hashdata, entry.size % len(hashdata),fp)

    os.close(fd)

def debug():
    pass

def main():
    if len(sys.argv) < 3:
        print("nvl_asar e(export) inpath [ourdir]")
        return
    
    inpath = sys.argv[2]
    if sys.argv[1].lower() == 'e': 
        outdir = sys.argv[3] if len(sys.argv) >= 4 else 'out'
        if not os.path.exists(outdir): os.makedirs(outdir)
        export_nvlasar(inpath, outdir)
    else: raise ValueError(f"{sys.argv[1]} not support!")


if __name__ == '__main__':
    # debug()
    main()