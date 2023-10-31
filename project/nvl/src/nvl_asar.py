# -*- coding: utf-8 -*-

"""
This is for decrypting asar file made by nvl cloud,
v0.3, developed by devseed

Tested game: OurEndOfTheWorld
"""

import os
import sys
import mmap
import json
import numpy as np
from io import BytesIO
# pip install pycryptodome
from Crypto.Cipher import AES
from typing import List, Dict, Tuple

# _pixiMiddleware, AES_CFB key iv from OurEndOfTheWorld, for other game, edit here
USE_PIXIMID = True #  enable PIXIMID decrypt
PIXIMID_KEY = bytes([142, 134, 122, 174, 139, 75, 85, 236, 1, 134, 58, 225, 136, 147, 59, 127])
PIXIMID_IV = bytes([196, 132, 205, 125, 176, 20, 171, 182, 209, 64, 82, 130, 168, 238, 166, 236])

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

def decrypt_nvlasarjpg(data: bytes, key: bytes, iv: bytes, 
    bufio: BytesIO=None) -> BytesIO:
    
    """
    decrypt with AES_CFB 
    """
    if bufio is None:
        bufio = BytesIO(data) # block size is 16
    cipher = AES.new(key, AES.MODE_CFB, iv, segment_size=128) 
    bufio.write(cipher.decrypt(data))
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

def get_nvlasar_index(data: bytes) -> Tuple[bytes, dict]:
    # decrypt nvl asar index
    print("decrypting nvl asar index ...")
    index_size = int.from_bytes(data[4:8], 'little', signed=False) - 8
    index_data = decrypt_nvlasar_batch(data[0x10:0x10+index_size], data[4:8], 0).getbuffer()
    index_data = bytes(index_data)
    index_end = index_data.rfind(b'\0')
    index_json = json.loads(index_data[:index_end].decode())
    return index_data, index_json

def get_nvlasar_list(index_json: json) -> List[nvlasar_entry_t]:
    
    # parse nvl asar index
    print("parsing nvl asar content ...")
    filestack = [{"obj": index_json, "objdir": ""}]
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
    return nvlasar_entries

def get_nvlasar_hashmap(data: bytes, content_offset: int, 
    nvlasar_entries: List[nvlasar_entry_t]) -> Dict[str, str]:
    
    # find assets.json
    nvlasar_map = dict()
    for entry in nvlasar_entries:
        if entry.name == "assets.json":
                start = content_offset + entry.offset
                hashdata = entry.hashstr.encode() + \
                    int.to_bytes(entry.size, 4, 'little', signed=False)
                mapdata = decrypt_nvlasar_batch(data[start: start + entry.size], 
                    hashdata, entry.size % len(hashdata)).getbuffer()
                asset_json = json.loads(bytes(mapdata).decode())
                break

    if asset_json:
        for k, v in asset_json.items():
            nvlasar_map.update({v: k})

    return nvlasar_map

def dump_nvlasar_entries(data: bytes, content_offset: int, 
    nvlasar_entries: List[nvlasar_entry_t], 
    nvlasar_map: Dict[str, str], outdir: str):
    
    # decrypt nvl asar content
    for i, entry in enumerate(nvlasar_entries):
        if entry.name in nvlasar_map:
            path = os.path.join(outdir, nvlasar_map[entry.name])
            path = path.replace('/', os.path.sep)
        else: 
            path = os.path.join(outdir, entry.curdir, entry.name)
        targetdir = os.path.dirname(path)
        if not os.path.exists(targetdir): os.makedirs(targetdir)
        
        print(f"{i+1}/{len(nvlasar_entries)} {path} "
            f"size={entry.size:x} offset={entry.offset:x} hash={entry.hashstr}")

        with open(path, "wb") as fp:
            item_offset = content_offset + entry.offset
            hashdata = entry.hashstr.encode() + \
                int.to_bytes(entry.size, 4, 'little', signed=False)
            extname = os.path.splitext(path)[1].lower()
            if  extname not in {".jpg", ".png"} or not USE_PIXIMID: 
                decrypt_nvlasar_batch(data[item_offset: item_offset + entry.size], 
                    hashdata, entry.size % len(hashdata), fp)
            else:  #  use pixiMiddleware AES_CFB
                _dataio = decrypt_nvlasar_batch(data[item_offset: item_offset + entry.size], 
                    hashdata, entry.size % len(hashdata))
                decrypt_nvlasarjpg(_dataio.getbuffer(), PIXIMID_KEY, PIXIMID_IV, fp)

def export_nvlasar(inpath, outdir):

    fd = os.open(inpath, os.O_RDWR)
    m = mmap.mmap(fd, 0)

    index_data, index_json = get_nvlasar_index(m)
    index_size = len(index_data)
    with open(os.path.join(outdir, "nvlasar_index.json"), "w") as fp:
        json.dump(index_json, fp, indent=2)

    nvlasar_entries = get_nvlasar_list(index_json)
    nvlasar_map = get_nvlasar_hashmap(m, index_size + 0x10, nvlasar_entries)
    dump_nvlasar_entries(m, index_size + 0x10, 
        nvlasar_entries, nvlasar_map, outdir)

    os.close(fd)

def debug():
    export_nvlasar(r"D:\Download\tmp\game.asar", r"D:\Download\tmp\out2")
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