# -*- coding: utf-8 -*-
__description__ = """
export or import ws2 text for willplus advhd, 
    v0.2.7, developed by devseed

tested games: 
    BlackishHouse (v1.6.2.1)
    華は短し、踊れよ乙女 (v1.9.9.9)
    
"""

__version__ = 270

import os
import sys
from collections import namedtuple
from typing import List

sys.path.append(os.path.join(os.path.dirname(__file__), r"compat"))
try:
    from compat.libutil_v600 import save_ftext, load_ftext, jtable_t, ftext_t
    from compat.libtext_v620 import insert_ftexts
except ImportError as e:
    exec("from compat.libutil_v600 import save_ftext, load_ftext, jtable_t, ftext_t")
    exec("from compat.libtext_v620 import insert_ftexts")

# ws2 functions
ws2name_t = namedtuple("ws2name_t", ['addr', 'size', 'text'])
ws2option_t = namedtuple("ws2option_t", ['addr', 'size', 'text', 'rawaddr', 'rawsize'])
ws2text_t = namedtuple("ws2text_t", ['addr', 'size', 'text'])

def export_ws2(inpath, outpath="out.txt", encoding='sjis'):
    with open(inpath, 'rb') as fp:
        data = bytearray(fp.read())
    
    # find text to extract
    # should consider about the overlap with name char %LC, and filter this
    names: List[ws2name_t] = []
    cur = 0
    pattern = b'%LC'
    while True:
        cur = data.find(pattern, cur)
        if cur < 0: break
        textaddr = cur
        textsize = data.find(b'\x00', textaddr) - textaddr
        text = data[textaddr: textaddr+textsize].decode(encoding)
        if not (cur > 5 and data[cur-5: cur] == b"char\0"):
            names.append(ws2name_t(textaddr, textsize, text))
        cur +=  textsize + 1
    
    options: List[ws2option_t] = []
    cur = 0 # hard code fix for option 2, 3, 4
    for pattern in [b'\x00\x00\x0f\x02', b'\x00\x00\x0f\x03', b'\x00\x00\x0f\x04']:
        cur = 0
        while cur < len(data) :
            cur = data.find(pattern, cur)
            if cur < 0: break
            cur += len(pattern)
            noption = pattern[-1]
            if data[cur] == 0 and data[cur+1] == 0:
                continue
            for i in range(noption):
                rawaddr = cur
                textaddr = cur + 2
                textsize = data.find(b'\x00', textaddr) - textaddr
                text = data[textaddr: textaddr+textsize].decode(encoding)
                rawsize = data.find(b'\x00', textaddr+textsize+5)  - rawaddr + 1
                print("option %d/%d"%(i+1, noption), hex(textaddr), text)
                options.append(ws2option_t(textaddr, textsize, text, rawaddr, rawsize))
                cur += rawsize
    
    texts: List[ws2text_t] = []
    cur = 0
    pattern = b'char\x00'
    while True:
        cur = data.find(pattern, cur)
        if cur < 0: break
        textaddr = cur + len(pattern)
        textsize = data.find(b'\x00', textaddr) - textaddr
        text = data[textaddr: textaddr+textsize].decode(encoding)
        texts.append(ws2text_t(textaddr, textsize, text))
        cur +=  textsize + 1
    
    # merge text to ftext
    ftexts: List[ftext_t] = []
    ftexts.extend([ftext_t(x.addr, x.size, x.text) for x in names]) 
    ftexts.extend([ftext_t(x.addr, x.size, x.text) for x in options]) 
    ftexts.extend([ftext_t(x.addr, x.size, x.text) for x in texts]) 
    ftexts.sort(key=lambda x: x.addr)
    if outpath: save_ftext(ftexts, ftexts, outpath)

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
        pattern = bytes.fromhex("7F 00 00 00 80 3F 00 00 00 00")
        while True:
            cur = data.find(pattern, cur)
            if cur < 0: break
            addr = cur + len(pattern)
            _addjumpentry(addr)
            addr += 0x10
            _addjumpentry(addr)
            cur = addr + 4

        cur = 0 # fix BZnoa_04.ws2， BZhal_28.ws2
        pattern = bytes.fromhex("03 00 00 80 3F 00 00 00 00")
        while True:
            cur = data.find(pattern, cur)
            if cur < 0: break
            addr = cur + len(pattern)
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

        cur = 0 # fix BZkyo_06.ws2 option
        pattern = bytes.fromhex("03 00 00 00 00 00 00 00 00")
        while True:
            cur = data.find(pattern, cur)
            if cur < 0: break
            addr = cur + len(pattern)
            _addjumpentry(addr)
            cur = addr + 4

        cur = 0 # fix BZKyo_06g.ws2 branch
        pattern = b'\x01\x80'
        while True:
            cur = data.find(pattern, cur)
            if cur < 0: break
            addr = cur + len(pattern) + 0xa
            _addjumpentry(addr)
            cur = addr + 4
            if cur + 0xc < len(data) and data[cur: cur+2] == b'\x01\x02':
                addr = cur + 0xc
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
        while False: # this might not be addr 
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
    text_replace = {'〜':'~', '−':'-', '･':'.', '♪':'钅', 
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
    workflow = "D:/Make/reverse/BlackishHouse/workflow"
    target = "BZkyo_02c.ws2"
    # cli([__file__, "ecp932", 
    #      os.path.join(workflow, "2.pre/Rio2", target)])
    cli([__file__, "icp936", 
        os.path.join(workflow, "3.edit/Rio2_ftext", target + ".txt"), 
        os.path.join(workflow, "2.pre/Rio2", target )])

def cli(argv):
    def cmd_help():
        print(__description__)
        print("advhd_ws2 e[cp932] inpath [outpath]")
        print("advhd_ws2 i[cp936] inpath orgpath [outpath]")
        return

    def cmd_extract():
        outpath = argv[3] if len(argv) > 3 else "out.txt"
        export_ws2(argv[2], outpath, encoding=encoding)

    def cmd_insert():
        outpath = argv[4] if len(argv) > 4 else "out.ws2"
        import_ws2(argv[2], argv[3], outpath, encoding=encoding)  
    
    if len(argv) < 3: cmd_help(); return
    cmdtype = argv[1].lower()
    encoding = cmdtype[1:]
    if encoding == "": encoding = "cp932"
    if  cmdtype[0] == 'e': cmd_extract()
    elif cmdtype[0] == 'i': cmd_insert()
    else: raise ValueError(f"unknow format {argv[1]}")

if __name__ == '__main__':
    # debug()
    cli(sys.argv)

"""
history:
v0.1, initial version for BlackishHouse (v1.6.2.1)
v0.2, support 華は短し、踊れよ乙女 (v1.9.9.9)
v0.2.1, fix some opcode for 華は短し、踊れよ乙女
v0.2.2, add encoding option in cli and change to libtext v0.6.1, fix option bug
v0.2.3, makes name and text disjoint, fix BZKyo_06g.ws2 branch b'\x01\x81'
v0.2.4, fix option to "00 00 0F 02 FF" for BZhal_32.ws2
v0.2.5, fix \x1f bgm01 opcode pre addr wrong,  make some text not render in  BZkyo_02c.ws2
v0.2.6, fix BZkyo_06.ws2 "03 00 00 00 00 00 00 00 00"
v0.2.7, fix BZnoa_04.ws2, BZhal_28.ws2 "03 00 00 80 3F 00 00 00 00"
"""