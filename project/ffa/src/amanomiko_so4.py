"""
parsing SO4 file for for 天巫女姫, 
(gxxx.S04, not worked on AXXXX.SO4) 
  v0.1, developed by devseed
  
"""

import os
import sys
import struct
from collections import namedtuple
from typing import List

sys.path.append(os.path.join(os.path.dirname(__file__), "compat"))
import bintext_v580 as bintext

so4opindex_t = namedtuple("so4opindex_t", ['addr', 'optype', 'oplen'])
def parse_so4(data: bytes) -> List[so4opindex_t]:
    cur = 0
    opindexs: List[so4opindex_t] = []
    while cur + 4 < len(data):
        optype, oplen = struct.unpack("<HH", data[cur: cur + 4])
        opindex = so4opindex_t(cur, optype, oplen)
        opindexs.append(opindex)
        if oplen==0:
            raise ValueError(
                f"oplen=0, cur={cur:x}, optype=\
                {optype:x}, oplen={oplen:x}")
        cur += oplen
    return opindexs

def print_so4(so4path, filter_optype = {0x0488, 0x0015}):
    with open(so4path, 'rb') as  fp:
       data = fp.read()
    opindexs = parse_so4(data)
    for opindex in opindexs:
        if opindex.optype in filter_optype: continue
        opcodebytes = data[opindex.addr + 4: \
            opindex.addr + opindex.oplen]
        opcodestr = " ".join([f"{x:02x}" for x in opcodebytes])
        print(f"addr={opindex.addr:x}, type={opindex.optype:04x}, oplen={opindex.oplen:x} [{opcodestr}]")

def export_so4text(so4path, outpath="out.txt", encoding='sjis'):
    with open(so4path, 'rb') as  fp:
       data = fp.read()
    opindexs = parse_so4(data)
    ftexts = []

    # extract the title
    addr = 0x10
    size = opindexs[0].oplen - 0x10 - 1
    textdata = data[addr: addr+size] 
    text = textdata.decode(encoding)
    ftexts.append({'addr': addr, 
            'size': size, 'text': text})

    # extract the scenrio text
    for opindex in opindexs:
        # print(hex(opindex.addr), hex(opindex.oplen), text)
        addr = opindex.addr
        size = opindex.oplen
        if opindex.optype == 0x0488: # text
            addr += 0x10
            size -= 0x10 + 1 # without 00
        elif opindex.optype == 0x0015: # option
            addr += 0xa
            size -= 0xa + 1 # without 00
        else: continue

        textdata = data[addr: addr+size]        
        if size < 2 or textdata.find(b'\x00')!=-1: 
            continue
        text = textdata.decode(encoding)
        ftexts.append({'addr': addr, 
            'size': size, 'text': text})
    if outpath!="":
        bintext.dump_ftext(ftexts, ftexts, outpath)
    return ftexts
    
def import_so4text(ftextpath, orgpath, 
    outpath="out.SO4.dec", encoding='gbk', 
    replace_map={'〜':'~ ', '−':'-', '･':'.',  '♪':'#',  '・':'.', 'ｷ':'#',  'ﾀ':'#', 'ｧ':'#',  '⇒':'-',  '≫':'-'}):
    
    def _search_opindex(addr):
        start = 0
        end = len(opindexs)
        while start < end:
            middle = (start + end) // 2
            v1 = opindexs[middle].addr
            v2 = v1 + opindexs[middle].oplen
            if addr > v1 and addr < v2:
                return middle
            elif addr < v1:
                end = middle
            elif addr > v2:
                start = middle
        return -1

    def _adjust_addr(orgdata, targetbytes, 
            orgaddr, orgsize, shift, fargs_adjust):
        d = len(targetbytes) - orgsize
        if d > 0:
            print(f'at {orgaddr:x}, {len(targetbytes):x} > {orgsize} imported!')
        idx = _search_opindex(orgaddr)
        if idx < 0: raise ValueError(
            f"can not find addr {orgaddr:x}")
        orgdata[opindexs[idx].addr + shift + 2: \
                opindexs[idx].addr + shift + 4] = \
            int.to_bytes(opindexs[idx].oplen+d,2,'little')

    # parse so4 opcodes
    with open(orgpath, 'rb') as fp:
        data =  bytearray(fp.read())
    opindexs = parse_so4(data)
    opindexs.sort(key=lambda x: x.addr)

    # make jumptable
    jumptable = []
    for opindex in opindexs:
        if opindex.optype == 0x024f or \
            opindex.optype == 0x021b or opindex.optype == 0x021a:
            addr = opindex.addr + 4
            if addr > len(data): continue
            jumpto = int.from_bytes(
                data[addr: addr+4], 'little', signed=False)
            if jumpto > len(data): continue
        else: continue
        jumptable.append({
            'addr': addr, 'jumpto': jumpto, 
            'addr_new': addr, 'jumpto_new': jumpto
        })

    # patch text and rebuild pointer
    data = bintext.patch_ftextobj(ftextpath, data, "", 
        encoding=encoding, can_longer=True, can_shorter=True,
        replace_map=replace_map, padding_bytes=b'\x20', 
        jump_table=jumptable, f_adjust=_adjust_addr)

    for t in jumptable:
        if t['jumpto_new'] == t['jumpto']: continue
        # print(f"rebuild addr {t['addr']:x}->{t['addr_new']:x} "
        #     f"jumpto {t['jumpto']:x}->{t['jumpto_new']:x}")
        data[t['addr_new']: t['addr_new'] + 4] = \
            int.to_bytes(t['jumpto_new'], 
                4, 'little', signed=False)

    if outpath!="":
        with open(outpath, 'wb') as fp:
            fp.write(data)

    return data

def debug():
    print_so4("./build/intermediate/G1WIN/g0270.SO4.dec")
    # export_so4text("./build/intermediate/G1WIN/g0003.SO4.dec")
    # import_so4text("./build/intermediate/G1WIN_ftext/g0003.SO4.txt", "./build/intermediate/G1WIN/g0003.SO4.dec")
    pass

def main():
    if len(sys.argv) < 3:
        print("SO4 e inpath [outpath]")
        print("SO4 i inpath orgpath [outpath]")
        return
    if sys.argv[1].lower() == 'e':
        outpath = sys.argv[3] if len(sys.argv) > 3 else "out.txt"
        export_so4text(sys.argv[2], outpath)
    elif sys.argv[1].lower() == 'i':
        outpath = sys.argv[4] if len(sys.argv) > 4 else "out.bin"
        import_so4text(sys.argv[2], sys.argv[3], outpath)
    else: raise ValueError(f"unknow format {sys.argv[1]}")

if __name__ == '__main__':
    # debug()
    main()
    pass