"""
krkrz hxv4 xp3 file tool, using keys and contrl_block dumped by krkr_hxv4_dumpkey.js
supports unpack files namestype fakename (garbro), or dirhash/filehash (KrkrExtractForCxdecV2)
  v0.1, developed by devseed

hx to decrypt index (chacha20), cx to generate span key

tested games: 
  D.C.5 Plus Happiness ～ダ・カーポ5～プラスハピネス
  D.C. Re:tune ～ダ・カーポ～ リチューン
"""

__version__ = "v0.1"
__description__ = f"krkrz hxv4 xp3 file tool, {__version__}, by devseed"

import os
import io
import re
import sys
import mmap
import zlib
import shlex
import ctypes
import struct
import binascii
import argparse
from dataclasses import dataclass
from typing import List, Dict, Any

from Crypto.Cipher import ChaCha20 # pycryptodome

from krkr_xp3 import Xp3Entry, parse_xp3, decrypt_text
from krkr_hxcrypt import HxSchme, HxFilterKey, HxEncryption

class Xp3Hxv4_t(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("offset", ctypes.c_int64),
        ("fsize", ctypes.c_uint32),
        ("flags", ctypes.c_uint16),
    ]

@dataclass
class Hxv4Entry:
    id: int = 0
    key: int = 0
    fakename: str = None
    filehash: bytes = None
    dirhash: bytes = None

@dataclass
class Hxv4Param:
    key: bytes = b"\x00" * 32
    nonce: bytes = b"\x00" * 16
    filterkey: bytes = b"\x00" * 8
    mask: int = 0
    offset: int = 0
    randtype: int = 0
    prologorder: List[int] = None # 3 items
    oddbranchorder: List[int] = None #  5 items
    evenbranchorder: List[int] = None # 7 items

def convert_fakename_hxv4(d: int) -> str:
    s = ""
    while True:
        u = ((d & 0x3FFF) + 0x5000) & 0xffff;
        s += chr(u)
        d >>= 14;
        if d == 0: break
    return s

def decrypt_index_hxv4(data: memoryview, key: bytes, nonce: bytes) -> memoryview:
    cipher = ChaCha20.new(key=key, nonce=nonce[:8])
    cipher.seek(64) # counter = 1
    buf = memoryview(cipher.decrypt(data))
    return buf

def decrypt_content_hxv4(data: memoryview, filterkey: HxFilterKey) -> memoryview:
    def _span_dec_key(key):
        deckey = (key >> 8) & 0xff
        deckey |= (key >> 8) & 0xff00
        positions = [ (key >> 48) & 0xffff, (key >> 32) & 0xffff]
        fisrdeckey = key & 0xff
        if positions[0] == positions[1]: positions[1] += 1
        if fisrdeckey == 0: fisrdeckey = 0xa5
        fisrdeckey *= 0x1010101
        return deckey, fisrdeckey, positions
    
    def _decrypt_span(span, key, offset):
        deckey, fisrdeckey, positions = _span_dec_key(key)
        firstkeybuf = struct.pack("<I", fisrdeckey)
        
        # first decrypt
        for i in range(len(span)): 
            span[i] ^= firstkeybuf[i & 3]

        # fix decrypt
        keys = [deckey & 0xff, (deckey >> 8) & 0xff]
        for k, p in zip(keys, positions):
            if p >= offset and p - offset < len(span):
                span[p - offset] ^= k

    buf = memoryview(bytearray(data))
    header_key = filterkey.header_key
    span_key1, span_key2 = filterkey.span_key
    split_pos = filterkey.split_pos
    
    # decrypt header
    for i in range(min(len(buf), len(header_key))):
        buf[i] ^= header_key[i]
        
    # decrypt span1, span2
    _decrypt_span(buf[:split_pos], span_key1, 0)
    _decrypt_span(buf[split_pos:], span_key2, split_pos)
    
    return buf

def extract_entry(data: memoryview, xp3entry: Xp3Entry, filterkey: HxFilterKey, base_offset=0) -> memoryview:
    outio = io.BytesIO()
    
    for segm in xp3entry.segms:
        offset = base_offset + segm.offset
        segdata = data[offset: offset + segm.zsize]
        if segm.fsize != segm.zsize: 
            segdata = memoryview(bytearray(zlib.decompress(segdata)))
        segdata = decrypt_content_hxv4(segdata, filterkey)
        if len(segdata) > 5 and  segdata[0] == 0xfe and segdata[1] == 0xfe and segdata[3] == 0xff and segdata[4] == 0xfe:
            segdata = decrypt_text(segdata[5:], segdata[2])
        outio.write(segdata)    
    
    return outio.getbuffer()

def parse_hxv4(data: memoryview, key: bytes, nonce: bytes, show_log=True) -> List[Hxv4Entry]:
    """
    :key: 32 byte
    :nounce: 16 byte
    """

    def _read_int32(r: io.BytesIO) -> int:
        return struct.unpack('>i', r.read(4))[0]

    def _read_uint64(r: io.BytesIO) -> int:
        return struct.unpack('>Q', r.read(8))[0]

    def _read_string(r: io.BytesIO) -> str:
        length = _read_int32(r)
        buffer = r.read(length * 2)
        return buffer.decode('utf-16-le')

    def _read_byte_array(r: io.BytesIO) -> bytes:
        count = _read_int32(r)
        return r.read(count)

    def _read_array(r: io.BytesIO) -> List:
        count = _read_int32(r)
        array = [_read_object(r) for _ in range(count)]
        return array

    def _read_dictionary(r: io.BytesIO) -> Dict[str, Any]:
        count = _read_int32(r)
        dictionary = dict()
        for _ in range(count):
            k = _read_string(r)
            v = _read_object(r)
            dictionary[k] = v
        return dictionary

    def _read_object(r: io.BytesIO):
        obj_type = r.read(1)[0]
        if obj_type <= 0x01: return None
        elif obj_type == 0x02: return _read_string(r)
        elif obj_type == 0x03: return _read_byte_array(r)
        elif obj_type in (0x04, 0x05): return _read_uint64(r)
        elif obj_type == 0x81: return _read_array(r)
        elif obj_type == 0xC1: return _read_dictionary(r)
        else: raise ValueError(f"Unknown object type: {hex(obj_type)}")

    indexdata = zlib.decompress(decrypt_index_hxv4(data[16:], key, nonce)[4:])
    indexdata = memoryview(indexdata)
    r = io.BytesIO(indexdata)
    objects = _read_object(r)
    assert r.tell() == len(indexdata), "deserialize hxv4 object wrong"

    hxv4entries: List[Hxv4Entry] = []
    for i in range(0, len(objects), 2):
        dirhash = objects[i]
        subobjects = objects[i+1]
        for j in range(0, len(subobjects), 2):
            filehash = subobjects[j]
            entry_id, entry_key = subobjects[j+1][:2]
            hxv4entry = Hxv4Entry(entry_id, entry_key, convert_fakename_hxv4(entry_id), filehash, dirhash)
            entry_log = f"|hxv4 {len(hxv4entries):05d} id={entry_id} " + \
                        f"name={hxv4entry.fakename} key={entry_key:08x} " + \
                        f"filehash={binascii.hexlify(filehash).decode()} " + \
                        f"dirhash={binascii.hexlify(dirhash).decode()}"
            if show_log: print(entry_log)
            hxv4entries.append(hxv4entry)

    return hxv4entries

def print_xp3(inpath, key, nonce):
    fp = open(inpath, "rb")
    data = mmap.mmap(fp.fileno(), 0, access=mmap.ACCESS_READ)
    
    # parse xp3entry, hxv4entry
    xp3entries  = parse_xp3(data, show_log=True)
    for i, entry in enumerate(xp3entries):
        if entry.sig == b"Hxv4":
            hxv4index = Xp3Hxv4_t.from_buffer_copy(entry.data)
            hxv4encdata = data[hxv4index.offset: hxv4index.offset + hxv4index.fsize]
            hxv4entries = parse_hxv4(hxv4encdata, key, nonce, show_log=True)
            break
    data.close()
    fp.close()

def unpack_xp3(inpath, cryptparam: Hxv4Param, block: bytes, namestyle="fakename", outdir = "out"):
    fp = open(inpath, "rb")
    data = mmap.mmap(fp.fileno(), 0, access=mmap.ACCESS_READ)
    
    # parse xp3entry, hxv4entry
    hxv4entries = None
    xp3entries  = parse_xp3(data, show_log=False)
    fakenamemap: Dict[str, int] = dict() 
    for i, entry in enumerate(xp3entries):
        if entry.sig == b"Hxv4":
            hxv4index = Xp3Hxv4_t.from_buffer_copy(entry.data)
            hxv4encdata = data[hxv4index.offset: hxv4index.offset + hxv4index.fsize]
            hxv4entries = parse_hxv4(hxv4encdata, cryptparam.key, cryptparam.nonce, show_log=False)
        elif entry.sig == b"File":
            if entry.name: fakenamemap[entry.name] = i

    # init HxEncryption scheme
    scheme = HxSchme()
    scheme.filter_key = cryptparam.filterkey
    scheme.random_type = cryptparam.randtype
    scheme.offset = cryptparam.offset
    scheme.mask = cryptparam.mask
    scheme.prolog_order = cryptparam.prologorder
    scheme.odd_branch_order = cryptparam.oddbranchorder
    scheme.even_branch_order = cryptparam.evenbranchorder
    scheme.control_block = [0] * 1024
    for i in range(1024):
        scheme.control_block[i] = ~struct.unpack_from("<I", block, i*4)[0]
    hxcrypt = HxEncryption(scheme)

    # extract files
    for i, hxv4entry in enumerate(hxv4entries):
        xp3entry = xp3entries[fakenamemap[hxv4entry.fakename]]
        hxfilterkey = hxcrypt.create_filter_key(hxv4entry.key, hxv4entry.id)
        outdata = extract_entry(data, xp3entry, hxfilterkey)

        # prepare path to write
        dirhashstr = binascii.hexlify(hxv4entry.dirhash).decode()
        filehashstr = binascii.hexlify(hxv4entry.filehash).decode()
        if namestyle == "fakename": subpath = f"{xp3entry.name}"
        else: subpath = os.path.join(dirhashstr, filehashstr)
        outpath = os.path.join(outdir, subpath)
        tmpdir = os.path.dirname(outpath)
        if not os.path.exists(tmpdir): os.makedirs(tmpdir)

        # save decrypted content
        print(f"[unpack_xp3] {i+1}/{len(hxv4entries)} {subpath} fsize=0x{len(outdata):x}")
        with open(outpath, "wb") as fp2:
            fp2.write(outdata)

    data.close()
    fp.close()

def cli(cmdstr=None):
    p = argparse.ArgumentParser(description=__description__)
    p.add_argument("method", choices=["unpack", "print"])
    p.add_argument("inpath", help="file path or dir path")
    p.add_argument("-o", "--outpath", default="out")
    p.add_argument("--key", default=None, help="hxv4 index key 32 bytes")
    p.add_argument("--nonce", default=None, help="hxv4 index nonce 16 bytes")
    p.add_argument("--filterkey", default=None, help="hxv4 content filter key 8 bytes")
    p.add_argument("--mask", default=None, help="hxv4 content cipter mask")
    p.add_argument("--offset", default=None, help="hxv4 content cipter offset")
    p.add_argument("--randtype", default=None, help="hxv4 content cipter randtype")
    p.add_argument("--prologorder", default=None, help="hxv4 content cipter PrologOrder (garbro)")
    p.add_argument("--oddbranchorder", default=None, help="hxv4 content cipter OddBranchOrder (garbro)")
    p.add_argument("--evenbranchorder", default=None, help="hxv4 content cipter EvenBranchOrder (garbro)")
    p.add_argument("--parampath", default=None, help="hxv4 crypt params by 'krkr_hxv4_dumpkey.js'")
    p.add_argument("--blockpath", default=None, help="hxv4 control block binary filepath")
    p.add_argument("--namestyle", default="fakename", choices=["fakename", "hash"])
    if cmdstr is None and len(sys.argv) < 2:
        p.print_help()
        return

    args = p.parse_args(shlex.split(cmdstr, posix=False) if cmdstr is not None else None)
    method, inpath, outpath = args.method, args.inpath, args.outpath
    parampath, blockpath = args.parampath, args.blockpath
    param, block = Hxv4Param(), b""
    namestyle = args.namestyle
    if parampath:
        with open(parampath, "rt") as fp:
            for line in fp.readlines():
                line = line.rstrip("\n").rstrip("\r")
                if m:=re.search(r" key : (.+?)$", line):
                    param.key = binascii.unhexlify(m.group(1))
                elif m:=re.search(r" nonce : (.+?)$", line):
                    param.nonce = binascii.unhexlify(m.group(1))
                elif m:=re.search(r" filterkey : (.+?)$", line):
                    param.filterkey = binascii.unhexlify(m.group(1))
                elif m:=re.search(r" mask : (.+?)$", line):
                    param.mask = int(m.group(1), base=0)
                elif m:=re.search(r" offset : (.+?)$", line):
                    param.offset = int(m.group(1), base=0)
                elif m:=re.search(r" randtype : (.+?)$", line):
                    param.randtype = int(m.group(1), base=0)
                elif m:=re.search(r" PrologOrder(.+?) : (.+?)$", line):
                    s = m.group(2)
                    param.prologorder = [int(x) for x in s.split(",")]
                elif m:=re.search(r" OddBranchOrder(.+?) : (.+?)$", line):
                    s = m.group(2)
                    param.oddbranchorder = [int(x) for x in s.split(",")]
                elif m:=re.search(r" EvenBranchOrder(.+?) : (.+?)$", line):
                    s = m.group(2)
                    param.evenbranchorder = [int(x) for x in s.split(",")]
    else:
        param.key = binascii.unhexlify(args.key)
        param.nonce = binascii.unhexlify(args.nonce)
        param.filterkey = binascii.unhexlify(args.filterkey)
        param.mask = int(args.mask, 0)
        param.offset = int(args.offset, 0)
        param.randtype = int(args.randtype, 0)
        param.prologorder = [int(x) for x in args.prologorder.replace(" ", "").split(",")]
        param.oddbranchorder = [int(x) for x in args.oddbranchorder.replace(" ", "").split(",")]
        param.evenbranchorder = [int(x) for x in args.evenbranchorder.replace(" ", "").split(",")]

    if method == "print":
        print_xp3(inpath, param.key, param.nonce)
    if method == "unpack":
        with open(blockpath, "rb") as fp:
            block = fp.read()
            assert len(block) == 4096, f"block size {len(block)} != 4096"
        unpack_xp3(inpath, param, block, namestyle=namestyle, outdir=outpath)

if __name__ == "__main__":
    cli()