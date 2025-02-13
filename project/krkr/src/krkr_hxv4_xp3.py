"""
extract hxv4 xp3 files
  v0.1, developed by devseed

xp3 <- [files entry] <- [info | segm | adlr]
hx to decrypt index, cx to decrypt content

refer:
  https://github.com/crskycode/GARbro/blob/master/ArcFormats/KiriKiri/HxCrypt.cs

tested games:  (not finished)
  D.C.5 Plus Happiness ～ダ・カーポ5～プラスハピネス

"""

import os
import io
import sys
import mmap
import zlib
import struct
import ctypes
from Crypto.Cipher import ChaCha20
from dataclasses import dataclass
from typing import List, Tuple, Dict

# TVP constant
XP3_SIG = bytes.fromhex("58 50 33 0D 0A 20 0A 1A 8B 67 01")

class Xp3Hxv4_t(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("offset", ctypes.c_int64),
        ("fsize", ctypes.c_uint32),
        ("flags", ctypes.c_uint16),
    ]

class Xp3Info_t(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("flags", ctypes.c_uint32), # compressed
        ("fsize", ctypes.c_int64),
        ("zsize", ctypes.c_int64),
        ("namelen", ctypes.c_uint16)
    ]

class Xp3Segm_t(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("flags", ctypes.c_uint32), # encrypted
        ("offset", ctypes.c_uint64),
        ("fsize", ctypes.c_uint64),
        ("zsize", ctypes.c_uint64)
    ]

class Xp3Adlr_t(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("hash", ctypes.c_uint32)
    ]

@dataclass
class Xp3Entry:
    info: Xp3Info_t = None
    adlr: Xp3Adlr_t = None
    segms: List[Xp3Segm_t] = None
    name = None

@dataclass
class HxEntry:
    pass

def parse_xp3(data: memoryview, base_offset=0, show_log=True) -> Tuple[List[Xp3Entry], Xp3Entry]:    
    assert(data.read(len(XP3_SIG)) == XP3_SIG)
    data_offset = int.from_bytes(data.read(8), 'little', signed=False)
    
    # https://github.com/krkrz/krkr2/blob/master/kirikiri2/tags/2.22rev2/base/XP3Archive.cpp
    if struct.unpack_from("<I", data, data_offset)[0] == 0x80: # will jmp, this is the special situation for cx
        data_offset = base_offset + struct.unpack_from("<Q", data, data_offset+9)[0];
        assert(data_offset >= 0x13 and data_offset < len(data))
    compres_flag = data[data_offset]
    assert(compres_flag == 0 or compres_flag == 1)

    # get index data
    index_data = None
    if compres_flag:
        zsize, fsize = struct.unpack_from("<QQ", data, data_offset + 1)
        zdata = data[data_offset + 17: data_offset + 17 + zsize]
        index_data = zlib.decompress(zdata)
    else:
        fsize,  = struct.unpack_from("<Q", data, data_offset + 1)
        index_data = data[data_offset + 9: data_offset + 9 + fsize]
    assert(index_data != None and len(index_data) == fsize)

    # parse entries
    i = 0
    index_start = 0
    hxv4 = None
    entries: List[Xp3Entry] = []
    while index_start < len(index_data) and index_data[index_start] != 0xff:
        entry_sig, entry_size = struct.unpack_from("<4sq", index_data, index_start)
        entry_log = f"|{i:05d} {entry_sig.decode()} (start=0x{index_start:x} size=0x{entry_size:x})"
        if show_log: print(entry_log)
        i += 1

        entry_start = 12
        if entry_sig == b"File":
            entry = Xp3Entry()
            while entry_start < entry_size:
                chunk_sig, chunk_size = struct.unpack_from("<4sq", index_data, index_start + entry_start)
                chunk_log = f"  |{chunk_sig.decode()} (start=0x{entry_start:x} size=0x{chunk_size:x})"

                if chunk_sig == b"info": # file info
                    info = Xp3Info_t.from_buffer_copy(index_data, index_start + entry_start + 12)
                    name_len = info.namelen
                    name_start = index_start + entry_start + 12 + ctypes.sizeof(info)
                    if name_len > 0 and name_len*2 + ctypes.sizeof(info) < chunk_size: # chunk_size without sig
                        try:
                            entry.name = index_data[name_start: name_start+name_len*2].decode("utf-16-le")
                        except UnicodeDecodeError:
                            pass
                    entry.info = info
                    chunk_log += f" flags={info.flags} fsize=0x{info.fsize:x} zsize=0x{info.fsize:x} name={entry.name}"
                
                elif chunk_sig == b"segm": # file content
                    j = 0
                    if entry.segms is None: entry.segms = []
                    for chunk_start in range(0, chunk_size, ctypes.sizeof(Xp3Segm_t)):
                        segm = Xp3Segm_t.from_buffer_copy(index_data, index_start + entry_start + 12 + chunk_start)
                        chunk_log += f"\n    |{j} flags={segm.flags} offset=0x{segm.offset:x} fsize=0x{segm.fsize:x} zsize=0x{segm.zsize:x}"
                        entry.segms.append(segm)
                        j += 1
                
                elif chunk_sig == b"adlr": # file hash
                    if chunk_size == 4:
                        entry.adlr = Xp3Adlr_t.from_buffer_copy(index_data, index_start + entry_start + 12)
                        chunk_log += f" hash=0x{entry.adlr.hash:08x}"
                
                entry_start += 12 + chunk_size
                if show_log: print(chunk_log)
            entries.append(entry)
        
        elif entry_sig == b"Hxv4":
            hxv4 = Xp3Hxv4_t.from_buffer_copy(index_data, index_start + entry_start)
            pass
        
        index_start += 12 + entry_size

    return entries, hxv4

def parse_hxv4(data: memoryview, hxv4: Xp3Hxv4_t, key=None, nonce=None) -> Dict[str, HxEntry]:
    """
    :key: 32 byte
    :nounce: 16 byte
    """
    return None

def filter_seg(segdata: memoryview, segm: Xp3Segm_t, hash=0, hxinfo=None, cxinfo=None) -> memoryview:
    """
    similar to cx with control block
    """
    return segdata

def extract_content(data: memoryview, entry: Xp3Entry, base_offset=0, hxinfo=None) -> memoryview:
    outio = io.BytesIO()
    
    for segm in entry.segms:
        offset = base_offset + segm.offset
        segdata = data[offset: offset + segm.zsize]
        if segm.fsize != segm.zsize: 
            segdata = memoryview(bytearray(zlib.decompress(segdata)))
        segdata = filter_seg(segdata, segm, entry.adlr.hash, hxinfo)
        outio.write(segdata)    
    
    return outio.getbuffer()

def extract_xp3(inpath, outdir = "out", key=None, nonce=None):
    fp = open(inpath, "rb")
    data = mmap.mmap(fp.fileno(), 0, access=mmap.ACCESS_READ)
    
    entries, hxv4 = parse_xp3(data)
    hxinfo = parse_hxv4(data, hxv4, key, nonce)

    for i, entry in enumerate(entries):
        # decrypt and extract content
        outdata = extract_content(data, entry, hxinfo=hxinfo)

        # prepare path to write
        if entry.info.namelen > 1: subpath = entry.name
        else: subpath = f"{i:05d}_{entry.adlr.hash:08x}_{entry.name}"
        outpath = os.path.join(outdir, subpath)
        tmpdir = os.path.dirname(outpath)
        if not os.path.exists(tmpdir): os.makedirs(tmpdir)

        # save decrypted content
        print(f"extract {subpath} with 0x{len(outdata):x} size")
        with open(outpath, "wb") as fp2:
            fp2.write(outdata)

    data.close()
    fp.close()

def debug():
    indir = r"d:/Game/pc/pc_galgame/[240927][vndb-v36687]DC5PH_jp[1PC,krkr]"
    extract_xp3(os.path.join(indir, "data.xp3"), os.path.join(indir, "out/data"))
    pass

def cli(argv=sys.argv):
    pass

if __name__ == "__main__":
    cli()
    debug()
    pass