"""
krkr2 xp3 file tool (support xp3filter)
  v0.1.1, developed by devseed

xp3 <- [files entry] <- [info | segm | adlr]

krkr2 xp3 file header:
XP3_SIG  11 // 58 50 33 0D 0A 20 0A 1A 8B 67 01, 0x11
index_offset 8 // often at the end of the file
... // file content

krkr2 xp3 index header: 
compress_flag 1
zsize 8 fsize 8, fsize 8 // if compress_flag, hase zsize
[entry_sig 4, entry_size 8, // File
    [subentry_sig 4, subentry_size 8, ...] *n // info, seg, adlr
] * n
"""

__version__ = "v0.1.1"
__description__ = f"krkr2 xp3 file tool, {__version__}, by devseed"

import os
import io
import sys
import zlib
import mmap
import shlex
import ctypes
import struct
import argparse
from dataclasses import dataclass
from typing import List, Callable

# TVP constant
XP3_SIG = bytes.fromhex("58 50 33 0D 0A 20 0A 1A 8B 67 01")
TVP_XP3_INDEX_ENCODE_METHOD_MASK = 0x07 # TVP_XP3_INDEX for krkrz xp3, not used here
TVP_XP3_INDEX_ENCODE_RAW = 0
TVP_XP3_INDEX_ENCODE_ZLIB = 1
TVP_XP3_INDEX_CONTINUE = 0x80
TVP_XP3_FILE_PROTECTED = 1<<31
TVP_XP3_SEGM_ENCODE_METHOD_MASK = 0x07
TVP_XP3_SEGM_ENCODE_RAW = 0
TVP_XP3_SEGM_ENCODE_ZLIB = 1

# xp3 struct
class Xp3Info_t(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("flags", ctypes.c_uint32), # TVP_XP3_FILE_PROTECTED
        ("fsize", ctypes.c_int64),
        ("zsize", ctypes.c_int64),
        ("namelen", ctypes.c_uint16)
        # after that is name content
    ]

class Xp3Segm_t(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("flags", ctypes.c_uint32), # TVP_XP3_SEGM_ENCODE_RAW, TVP_XP3_SEGM_ENCODE_ZLIB
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
    sig: str = None # entry sig "FILE"
    data: memoryview = None # raw bytes of entry
    info: Xp3Info_t = None
    adlr: Xp3Adlr_t = None
    segms: List[Xp3Segm_t] = None
    name = None

xp3filter_t = Callable[[int, int, memoryview, int], None]

def xp3filter_dummy(hash, offset, buf, buflen):
    pass

def update_adler32(data: memoryview, adler: int) -> int:
    BASE = 65521
    NMAX = 5552
    sum2 = (adler >> 16) & 0xFFFF
    adler &= 0xFFFF
    
    length = len(data)
    index = 0
    
    if length == 1:
        adler += data[0]
        if adler >= BASE:
            adler -= BASE
        sum2 += adler
        if sum2 >= BASE:
            sum2 -= BASE
        return (sum2 << 16) | adler
    
    if length < 16:
        for byte in data:
            adler += byte
            sum2 += adler
        adler %= BASE
        sum2 %= BASE
        return (sum2 << 16) | adler
    
    while length >= NMAX:
        length -= NMAX
        for i in range(0, NMAX, 16):
            for j in range(16):
                adler += data[index + j]
                sum2 += adler
            index += 16
        adler %= BASE
        sum2 %= BASE
    
    if length:
        for i in range(0, length, 16):
            for j in range(min(16, length - i)):
                adler += data[index + j]
                sum2 += adler
            index += 16
        adler %= BASE
        sum2 %= BASE
    
    return (sum2 << 16) | adler

def decrypt_text(data: memoryview, enc_type=1) -> memoryview:
    if enc_type == 2:
        zsize, fsize = struct.unpack("<qq", data)
        return memoryview(zlib.decompress(data[16:]))

    outio = io.BytesIO()
    outio.write(b"\xff\xfe")
    if enc_type == 1:
        for i in range(0, len(data), 2):
            d = struct.unpack_from("<H", data, i)[0]
            d = (d & 0xAAAA) >> 1 | (d & 0x5555) << 1
            outio.write(struct.pack("<H", d))
    else:
        for i in range(0, len(data), 2):
            d = struct.unpack_from("<H", data, i)[0]
            if d > 0x20:
                d = d ^ (((d & 0xFE) << 8) ^ 1)
                outio.write(struct.pack("<H", d))

    return outio.getbuffer()

def extract_entry(data: memoryview, entry: Xp3Entry, base_offset=0, xp3filter: xp3filter_t=None) -> memoryview:
    outio = io.BytesIO()
    
    for segm in entry.segms:
        offset = base_offset + segm.offset
        segdata = data[offset: offset + segm.zsize]
        if (segm.flags & TVP_XP3_SEGM_ENCODE_METHOD_MASK) == TVP_XP3_SEGM_ENCODE_ZLIB: 
            segdata = memoryview(bytearray(zlib.decompress(segdata)))
        if xp3filter: 
            segdata = memoryview(bytearray(segdata))
            xp3filter(entry.adlr.hash, 0, segdata, len(segdata))
        if len(segdata) > 5 and  segdata[0] == 0xfe and segdata[1] == 0xfe and segdata[3] == 0xff and segdata[4] == 0xfe:
            segdata = decrypt_text(segdata[5:], segdata[2])
        outio.write(segdata)    
    
    return outio.getbuffer()

def parse_xp3(data: memoryview, base_offset=0, show_log=True) -> List[Xp3Entry]:    
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
    index_data = memoryview(index_data)

    # parse entries
    i = 0
    index_start = 0
    entries: List[Xp3Entry] = []
    while index_start < len(index_data) and index_data[index_start] != 0xff:
        entry_sig, entry_size = struct.unpack_from("<4sq", index_data, index_start)
        entry_log = f"|{i:05d} {entry_sig.decode()} (start=0x{index_start:x} size=0x{entry_size:x})"
        if show_log: print(entry_log)
        i += 1

        entry_start = 12
        entry_data = index_data[index_start + entry_start: index_start + entry_start + entry_size]
        entry = Xp3Entry(sig = entry_sig, data=entry_data)
        if entry_sig == b"File":
            while entry_start < entry_size:
                chunk_sig, chunk_size = struct.unpack_from("<4sq", index_data, index_start + entry_start)
                chunk_log = f"  |{chunk_sig.decode()} (start=0x{entry_start:x} size=0x{chunk_size:x})"

                if chunk_sig == b"info": # file info
                    info = Xp3Info_t.from_buffer_copy(index_data, index_start + entry_start + 12)
                    name_len = info.namelen
                    name_start = index_start + entry_start + 12 + ctypes.sizeof(info)
                    if name_len > 0 and name_len*2 + ctypes.sizeof(info) <= chunk_size: # chunk_size without sig
                        try:
                            entry.name = index_data[name_start: name_start+name_len*2].tobytes().decode("utf-16le")
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

                if show_log: print(chunk_log)
                entry_start += 12 + chunk_size

        entries.append(entry)
        index_start += 12 + entry_size

    return entries

def print_xp3(inpath):
    with open(inpath, "rb") as fp:
        with mmap.mmap(fp.fileno(), 0, access=mmap.ACCESS_READ) as data:
            parse_xp3(data, show_log=True)

def unpack_xp3(inpath, outdir="out", xp3filter: xp3filter_t=None):
    fp = open(inpath, "rb")
    data = mmap.mmap(fp.fileno(), 0, access=mmap.ACCESS_READ)
    
    entries = parse_xp3(data, show_log=False)

    for i, entry in enumerate(entries):
        # decrypt and extract content
        if entry.segms is None: continue 
        outdata = extract_entry(data, entry, 0, xp3filter)

        # prepare path to write
        if entry.info.namelen > 1: subpath = entry.name
        else: subpath = f"{i:05d}_{entry.adlr.hash:08x}_{entry.name}"
        outpath = os.path.join(outdir, subpath)
        tmpdir = os.path.dirname(outpath)
        if not os.path.exists(tmpdir): os.makedirs(tmpdir)

        # save decrypted content
        print(f"[unpack_xp3] {i+1}/{len(entries)} {subpath} fsize=0x{len(outdata):x}")
        with open(outpath, "wb") as fp2:
            fp2.write(outdata)

    data.close()
    fp.close()

def pack_xp3(indir, outpath, compress="none", xp3filter: xp3filter_t=None):
    compress_index = True if compress.lower() in {"index", "all"} else False
    compress_content = True if compress.lower() in {"content", "all"} else False
    
    # find files
    inpaths = []
    for root, dirs, files in os.walk(indir):
        for file in files:
            inpath = os.path.relpath(os.path.join(root, file), indir)
            inpath = inpath.replace("\\", "/").rstrip("/").lstrip(".").lstrip("/")
            inpaths.append(inpath)
    
    # write header
    outio = io.BytesIO()
    outio.write(XP3_SIG)
    outio.write(b"\x00" * 8) # preserve index offset 

    # write xp3 content and make entries
    entries: List[Xp3Entry] = []
    for i, inpath in enumerate(inpaths):
        info, segm, adlr = Xp3Info_t(), Xp3Segm_t(), Xp3Adlr_t()
        with open(os.path.join(indir, inpath), "rb") as fp:
            data = memoryview(fp.read())
        info.flags = TVP_XP3_FILE_PROTECTED
        info.fsize = len(data)
        info.namelen, info.name = len(inpath), inpath
        segm.fsize = len(data)
        segm.offset = outio.tell()
        adlr.hash = update_adler32(data, 1)
        if xp3filter:
            data = memoryview(bytearray(data))
            xp3filter(adlr.hash, 0, data, len(data))
        if compress_content: 
            data_compressed = zlib.compress(data)
            info.zsize =  len(data_compressed)
            segm.flags = TVP_XP3_SEGM_ENCODE_ZLIB
            segm.zsize = len(data_compressed)
            outio.write(data_compressed)
        else: 
            info.zsize =  len(data)
            segm.flags = TVP_XP3_SEGM_ENCODE_RAW
            segm.zsize = len(data)
            outio.write(data)

        print(f"[pack_xp3] {i+1}/{len(inpaths)} {inpath} fsize=0x{info.fsize} zsize=0x{info.zsize}")
        entry = Xp3Entry(info, adlr,[segm])
        entries.append(entry)

    # make xp3 entry data
    outio2 = io.BytesIO()
    for entry in entries:
        adlr, info, segm = entry.adlr, entry.info, entry.segms[0]
        adlrdata = b"adlr" + struct.pack("<q", ctypes.sizeof(Xp3Adlr_t)) + bytes(adlr)
        segmdata = b"segm" + struct.pack("<q", ctypes.sizeof(Xp3Segm_t)) + bytes(segm)
        infodata = b"info" + struct.pack("<q", ctypes.sizeof(Xp3Info_t) + 2 * (len(info.name) + 1)) + \
                        bytes(info) + info.name.encode("utf-16le") + b"\x00\x00"
        outio2.write(b"File" + struct.pack("<q", len(adlrdata) + len(segmdata) + len(infodata)))
        outio2.write(adlrdata)
        outio2.write(segmdata)
        outio2.write(infodata)

    # adjust offset
    index_offset = outio.tell()
    outio.getbuffer()[len(XP3_SIG): len(XP3_SIG) + 8] = struct.pack("<q", index_offset)
    if compress_index: 
        outio.write(b"\x01")
        data_compressed = zlib.compress(outio2.getbuffer())
        outio.write(struct.pack("<QQ", len(data_compressed), outio2.tell()))
        outio.write(data_compressed)
    else: 
        outio.write(b"\x00")
        outio.write(struct.pack("<Q", outio2.tell()))
        outio.write(outio2.getbuffer())

    with open(outpath, "wb") as fp:
        fp.write(outio.getbuffer())
    
def cli(cmdstr=None):
    p = argparse.ArgumentParser(description=__description__)
    p.add_argument("method", choices=["pack", "unpack", "print"])
    p.add_argument("inpath", help="file path or dir path")
    p.add_argument("-o", "--outpath", default="out")
    p.add_argument("-c", "--compress", choices=["none", "index", "content", "all"], default="none")
    if cmdstr is None and len(sys.argv) < 2:
        p.print_help()
        return

    args = p.parse_args(shlex.split(cmdstr, posix=False) if cmdstr is not None else None)
    method, inpath, outpath = args.method, args.inpath, args.outpath
    if method == "print":
        print_xp3(inpath)
    if method == "unpack":
        unpack_xp3(inpath, outpath, None)
    elif method == "pack":
        pack_xp3(inpath, outpath, args.compress, None)

if __name__ == "__main__":
    cli()

"""
history:
v0.1, initial version
v0.1.1, add other print_xp3, xp3entry raw data and decrypt_text
"""