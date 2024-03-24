# -*- coding: utf-8 -*-
__description__ = """
export or import ws2 text for willplus advhd, 
tested in BlackishHouse (v1.6.2.1), 華は短し、踊れよ乙女 (1.9.9.9)
    v0.2.2, developed by devseed
"""

__version__ = 220

import os
import sys
from collections import namedtuple
from typing import List

sys.path.append(os.path.join(os.path.dirname(__file__), r"compat"))
try:
    from compat.libutil_v600 import save_ftext, load_ftext, jtable_t
    from compat.libtext_v610 import insert_ftexts
except ImportError as e:
    exec("from compat.libutil_v600 import save_ftext, load_ftext, ftext_t")

# ws2 functions
ws2name_t = namedtuple("ws2name_t", ['addr', 'size', 'text'])
ws2option_t = namedtuple("ws2option_t", ['addr', 'size', 'text', 'rawaddr', 'rawsize'])
ws2text_t = namedtuple("ws2text_t", ['addr', 'size', 'text'])

def export_ws2(inpath, outpath="out.txt", encoding='sjis'):
    with open(inpath, 'rb') as fp:
        data = bytearray(fp.read())
    
    # find text to extract
    names: List[ws2name_t] = []
    cur = 0
    pattern = b'%LC'
    while True:
        cur = data.find(pattern, cur)
        if cur < 0: break
        addr = cur
        size = data.find(b'\x00', addr) - addr
        text = data[addr: addr+size].decode(encoding)
        names.append(ws2name_t(addr, size, text))
        cur +=  size + 1
    
    options: List[ws2option_t] = []
    cur = 0
    pattern = b'\x0f\x02'
    while True:
        oldcur = cur
        cur = data.find(pattern, cur)
        if cur < 0: cur = data.find(b'\x0f\x03', oldcur) # hard code fix for option 3
        if cur < 0: cur = data.find(b'\x0f\x04', oldcur) # hard code fix for option 4
        if cur < 0 or cur + 2 > len(data) -1: break
        cur = cur + len(pattern)
        if data[cur]==0 and data[cur+1]==0: 
            cur += 2
            continue
        while data[cur]!=0xff:
            rawaddr = cur
            addr = cur + 2
            size = data.find(b'\x00', addr) - addr
            text = data[addr: addr+size].decode(encoding)
            print(hex(addr), text)
            rawsize = data.find(b'\x00', addr+size+5)  - rawaddr + 1
            options.append(ws2option_t(
                addr, size, text, rawaddr, rawsize))
            cur += rawsize
        cur += 1
    
    texts: List[ws2text_t] = []
    cur = 0
    pattern = b'char\x00'
    while True:
        cur = data.find(pattern, cur)
        if cur < 0: break
        addr = cur + len(pattern)
        size = data.find(b'\x00', addr) - addr
        text = data[addr: addr+size].decode(encoding)
        texts.append(ws2text_t(addr, size, text))
        cur +=  size + 1
    
    # merge text to ftext
    ftexts = []
    ftexts.extend([{'addr': x.addr, 
        'size': x.size, 'text': x.text} for x in names]) 
    ftexts.extend([{'addr': x.addr, 
        'size': x.size, 'text': x.text} for x in options]) 
    ftexts.extend([{'addr': x.addr, 
        'size': x.size, 'text': x.text} for x in texts]) 
    ftexts.sort(key=lambda x: x['addr'])
    if outpath!="": save_ftext(ftexts, ftexts, outpath)

    return ftexts

def import_ws2(inpath, orgpath, outpath="out.ws2", encoding="gbk"):
    def _addjumpentry(addr):
        if addr > len(data): return False
        toaddr = int.from_bytes(data[addr: addr+4], 'little', signed=True)
        if toaddr < addr: return False
        if toaddr > 0 and toaddr < len(data):
            if addr in jump_set: return False
            jump_set.add(addr)
            jump_table.append(jtable_t(addr, addr, toaddr, toaddr))
            return True

    def _add_BlackishHouse_jumptable():
        cur = 0
        pattern = b'\x7F\x00\x00\x00\x80\x3F\x00\x00\x00\x00'
        while True:
            cur = data.find(pattern, cur)
            if cur < 0: break
            addr = cur + len(pattern)
            _addjumpentry(addr)
            addr += 0x10
            _addjumpentry(addr)
            cur = addr + 4

        cur = 0 # fix BZkyo_03f.ws2 option
        pattern = b'\x7F\x00\x00\x00\x00\x00\x00\x00\x00\x00'
        while True:
            cur = data.find(pattern, cur)
            if cur < 0: break
            addr = cur + len(pattern)
            if data[addr: addr + 4] != data[addr+0x10: addr+0x14]:
                cur += 1
                continue
            _addjumpentry(addr)
            addr += 0x10
            _addjumpentry(addr)
            cur = addr + 4

        cur = 0
        pattern = b'\x05\x00\x00\x00\x00\x00\x00\x00\x00'
        while True:
            cur = data.find(pattern, cur)
            if cur < 0: break
            addr = cur + len(pattern)
            _addjumpentry(addr)
            cur = addr + 4
        pass

    def _add_Hanaoto_jumptable():
        # (15 00)|32|04|02 00 E6 // +0, +4 
        patterns = [b'\x00\xE6', b'\x01\xE6']
        for pattern in patterns:
            cur = 0
            while True:
                cur = data.find(pattern, cur)
                if cur < 0: break
                if cur < 1: 
                    cur += len(pattern)
                elif data[cur-1] == 0x2 \
                    or data[cur-1] == 0x4\
                    or data[cur-1] == 0x32 \
                    or (cur > 1 and  (data[cur-1]==0x0 and data[cur-2]==0x15 )):
                    addr = cur + len(pattern)
                    _addjumpentry(addr)
                    addr += 4
                    _addjumpentry(addr)
                    cur = addr + 4
                else: cur += len(pattern)

        cur = 0
        pattern = b'GetMsgSkip'
        while True:
            cur = data.find(pattern, cur)
            if cur < 0: break
            addr = cur + len(pattern) + 0xd
            _addjumpentry(addr)
            cur = addr + 4
        
        cur = 0 # bgm
        pattern = b'\x1F\x62\x67\x6D'
        while True:
            cur = data.find(pattern, cur)
            if cur < 0: break
            addr = cur - 0x4
            _addjumpentry(addr)
            cur += len(pattern)

        cur = 0 # movie
        pattern = b'\x3A\x6D\x6F\x76\x69\x65'
        while True:
            cur = data.find(pattern, cur)
            if cur < 0: break
            addr = cur - 0x4
            _addjumpentry(addr)
            addr = addr - 0x4 # not for second movie
            _addjumpentry(addr) 
            cur += len(pattern)

    ftexts1, ftexts2 = load_ftext(inpath)
    with open(orgpath, 'rb') as fp:
        data = bytearray(fp.read())
    
    # make jump_table
    jump_table: List[jtable_t] = []
    jump_set = set()
    _add_BlackishHouse_jumptable()
    _add_Hanaoto_jumptable()

    # import text
    jump_table.sort(key=lambda x: x.addr)
    text_replace = {'〜':'~', '−':'-', '･':'.', '♪':'#', 
        '・':'.', 'ｷ':'#', 'ﾀ':'#',  
        'ｧ':'#', '⇒':'-', '≫':'-', '・':'.'}
    data = insert_ftexts(data, (ftexts1, ftexts2), 
                encoding=encoding, insert_longer=True, bytes_padding=b'\x20',
                text_replace=text_replace, jump_table=jump_table)
    data = memoryview(bytearray(data))
    
    # rebuild jumptable
    for t in jump_table:
        addr = t.addr
        addr_new = t.addr_new
        toaddr = t.toaddr
        toaddr_new = t.toaddr_new
        if addr == addr_new and toaddr == toaddr_new: continue
        print(f"rebuild addr 0x{addr:x}->0x{addr_new:x}," 
            f"jumpto 0x{toaddr:x}->0x{toaddr_new:x}")
        data[addr_new: addr_new+4] = int.to_bytes(toaddr_new, 4, 'little', signed=False)
    if outpath!="":
        with open(outpath, 'wb') as fp:
            fp.write(data)
    
    return data

def debug():
    pass

def cli(argv):
    def cmd_help():
        print(__description__)
        print("advhd_ws2 e inpath [outpath]")
        print("advhd_ws2 i[cp936] inpath orgpath [outpath]")
        return

    def cmd_extract():
        outpath = argv[3] if len(argv) > 3 else "out.txt"
        export_ws2(argv[2], outpath)

    def cmd_insert():
        encoding = cmdtype[1:]
        outpath = argv[4] if len(argv) > 4 else "out.ws2"
        import_ws2(argv[2], argv[3], outpath, encoding=encoding)  
    
    if len(argv) < 3: cmd_help(); return
    cmdtype = argv[1].lower()
    if  cmdtype == 'e': cmd_extract()
    elif cmdtype[0] == 'i': cmd_insert()
    else: raise ValueError(f"unknow format {argv[1]}")

if __name__ == '__main__':
    cli(sys.argv)

"""
history:
v0.1, initial version for BlackishHouse
v0.2, support 華は短し、踊れよ乙女 (1.9.9.9)
v0.2.1, fix some opcode for 華は短し、踊れよ乙女
v0.2.2, add encoding option in cli and change to libtext v0.6.1
"""