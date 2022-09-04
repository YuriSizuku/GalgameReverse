"""
export or import ws2 text for willplus advhd, 
tested in BlackishHouse (v1.6.2.1), 華は短し、踊れよ乙女 (1.9.9.9)
    v0.2, developed by devseed
"""

import re
import sys
import codecs
from io import BytesIO
from collections import namedtuple
from typing import Union, List, Dict, Callable, Any

# util functions
def dump_ftext(ftexts1:List[Dict[str,Union[int,str]]], 
    ftexts2: List[Dict[str, Union[int, str]]], 
    outpath: str="", *, num_width=5, 
    addr_width=6, size_width=3) -> List[str]:
    """
    ftexts1, ftexts2 -> ftext lines
    text dict is as {'addr':, 'size':, 'text':}
    :param ftexts1[]: text dict array in '○' line, 
    :param ftexts2[]: text dict array in '●' line
    :return: ftext lines
    """

    if num_width==0:
        num_width = len(str(len(ftexts1)))
    if addr_width==0:
        d = max([t['addr'] for t in ftexts1])
        addr_width = len(hex(d)) - 2
    if size_width==0:
        d = max([t['size'] for t in ftexts1])
        size_width = len(hex(d)) - 2

    fstr1 = "○{num:0"+ str(num_width) + "d}|{addr:0" + str(addr_width) + "X}|{size:0"+ str(size_width) + "X}○ {text}\n"
    fstr2 = fstr1.replace('○', '●')
    lines = []

    length = 0
    if ftexts1 == None: 
        length = len(ftexts2)
        fstr2 += '\n'
    if ftexts2 == None: 
        length = len(ftexts1)
        fstr1 += '\n'
    if ftexts1 != None and ftexts2 != None : 
        length = min(len(ftexts1), len(ftexts2))
        fstr2 += '\n'

    for i in range(length):
        if ftexts1 != None:
            t1 = ftexts1[i]
            lines.append(fstr1.format(
                num=i,addr=t1['addr'],size=t1['size'],text=t1['text']))
        if ftexts2 != None:
            t2 = ftexts2[i]
            lines.append(fstr2.format(
                num=i,addr=t2['addr'],size=t2['size'],text=t2['text']))

    if outpath != "":
        with codecs.open(outpath, 'w', 'utf-8') as fp:
            fp.writelines(lines)
    return lines 

def load_ftext(ftextobj: Union[str, List[str]], 
    only_text = False ) -> List[Dict[str, Union[int, str]]]:
    """
    ftext lines  -> ftexts1, ftexts2
    text dict is as {'addr':, 'size':, 'text':}
    :param inobj: can be path, or lines[] 
    :return: ftexts1[]: text dict array in '○' line, 
             ftexts2[]: text dict array in '●' line
    """

    ftexts1, ftexts2 = [], []
    if type(ftextobj) == str: 
        with codecs.open(ftextobj, 'r', 'utf-8') as fp: 
            lines = fp.readlines()
    else: lines = ftextobj

    if only_text == True: # This is used for merge_text
        re_line1 = re.compile(r"^○(.+?)○[ ](.*)")
        re_line2 = re.compile(r"^●(.+?)●[ ](.*)")
        for line in lines:
            line = line.strip("\n").strip('\r')
            m = re_line1.match(line)
            if m is not None:
                ftexts1.append({'addr':0,'size':0,'text': m.group(2)})
            m = re_line2.match(line)
            if m is not None:
                ftexts2.append({'addr':0,'size':0,'text': m.group(2)})
    else:
        re_line1 = re.compile(r"^○(\d*)\|(.+?)\|(.+?)○[ ](.*)")
        re_line2 = re.compile(r"^●(\d*)\|(.+?)\|(.+?)●[ ](.*)")
        for line in lines:
            line = line.strip("\n").strip('\r')
            m = re_line1.match(line)
            if m is not None:
                ftexts1.append({'addr':int(m.group(2),16),
                'size':int(m.group(3),16),'text': m.group(4)})
            m = re_line2.match(line)
            if m is not None:
                ftexts2.append({'addr':int(m.group(2),16),
                'size':int(m.group(3),16),'text': m.group(4)})
    return ftexts1, ftexts2

def patch_text(orgdata: bytearray, 
    ftexts: List[Dict[str, Union[int, str]]],
    encoding='utf-8', can_longer=False, can_shorter=False, 
    align=1, is_copy=False, is_mute=False, 
    replace_map: Dict[str, str]=None, padding_bytes=b'\x00'
    , *, jump_table: Dict[str, int]=None, 
    f_adjust: Callable[[bytearray, bytes, 
        int, int, int, Any], None]=None, fargs_adjust=None
    ) -> bytes:
    """
    :param data: bytearray
    :param encoding: the encoding of the original binary file if no tbl
    :param replace_map: a dict for replaceing char, {'a': 'b'} 
    :param padding_bytes: paddings if rebuild text shorter

    :param jump_table: a dict array with 
        {'addr':, 'addr_new':, 'jumpto':, 'jumpto_new':}
    :f_extension: parse the extension to replace, like {{\xab\xcd}}
    :f_adjust: some adjusting before import text,  
        f_adjust(data, targetbytes, orgaddr, orgsize, shift, fargs_adjust)
    """
    
    def _padding(n):
        l1 = n //len(padding_bytes)
        l2 = n % len(padding_bytes)
        return l1*padding_bytes + padding_bytes[:l2]

    if not is_copy: data = orgdata
    else: data = bytearray(orgdata)
    
    shift = 0
    ftexts.sort(key=lambda x: x['addr'])
    for _, ftext in enumerate(ftexts):
        addr, size, text = ftext['addr'], ftext['size'], ftext['text'] 
        # parse the patterns in text
        text = text.replace(r'[\n]', '\n')
        text = text.replace(r'[\r]', '\r')
        if replace_map is not None:
            for k, v in replace_map.items():
                text = text.replace(k, v)
        bufio = BytesIO()
        bufio.write(text.encode(encoding))

        # add padding for size
        if bufio.tell() <= size: 
            if not can_shorter:
                bufio.write(_padding(size-bufio.tell()))
        else: 
            if not is_mute:
                print("at 0x%06X, %d bytes is lager than %d bytes!"
                    %(addr, bufio.tell(), size))

        # add padding for align
        d = bufio.tell() - size
        if d % align != 0:
            if d > 0: # longer
                bufio.write(_padding(align - d%align))
            else: # shorter
                bufio.write(_padding(d%align))

        # patch the data
        if can_longer: targetbytes = bufio.getbuffer()
        else: targetbytes = bufio.getbuffer()[0:size]
        if f_adjust: # adjust some information before patch text
            f_adjust(data, targetbytes, 
                addr, size, shift, fargs_adjust)
        data[addr+shift: addr+shift+size] = targetbytes
        shift += len(targetbytes) - size
        
        # adjust the jump_table
        if jump_table is not None:
            for t in jump_table:
                if t['addr'] >= addr: 
                    t['addr_new'] = t['addr'] + shift
                if t['jumpto'] >= addr:  
                    t['jumpto_new'] = t['jumpto'] + shift
        
        if not is_mute:
            print("at 0x%06X, %d bytes replaced!" % (addr, size))
 
    return data

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
        cur = data.find(pattern, cur)
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
    if outpath!="":
        dump_ftext(ftexts, ftexts, outpath)

    return ftexts

def import_ws2(inpath, orgpath, outpath="out.ws2", encoding="gbk"):
    def _addjumpentry(addr):
        if addr > len(data): return False
        jumpto = int.from_bytes(data[addr: addr+4], 
            'little', signed=True)
        if jumpto < addr: return False
        if jumpto > 0 and jumpto < len(data):
            if addr in jump_set: return False
            jump_set.add(addr)
            jump_table.append({'addr': addr, 'jumpto': jumpto, 
                'addr_new': addr, 'jumpto_new': jumpto})
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
        cur = 0 # 15 00|32|02 00 E6 // +0, +4 
        pattern = b'\x00\xE6'
        while True:
            cur = data.find(pattern, cur)
            if cur < 0: break
            if cur < 1: 
                cur += len(pattern)
            elif data[cur-1] == 0x2 or data[cur-1] == 0x32 \
                    or (cur > 1 and  
                    (data[cur-1]==0x0 and data[cur-2]==0x15 )):
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
            cur += len(pattern)

    _, ftexts = load_ftext(inpath)
    with open(orgpath, 'rb') as fp:
        data = bytearray(fp.read())
    
    # make jump_table
    jump_table = []
    jump_set = set()
    _add_BlackishHouse_jumptable()
    _add_Hanaoto_jumptable()

    # import text
    jump_table.sort(key=lambda x: x['addr'])
    replace_map = {'〜':'~', '−':'-', '･':'.', '♪':'#', 
        '・':'.', 'ｷ':'#', 'ﾀ':'#',  
        'ｧ':'#', '⇒':'-', '≫':'-', '・':'.'}
    data = patch_text(data, ftexts, encoding=encoding, 
        can_longer=True, padding_bytes=b'\x20',
        replace_map=replace_map, jump_table=jump_table)
    
    # rebuild jumptable
    for entry in jump_table:
        addr = entry['addr']
        addr_new = entry['addr_new']
        jumpto = entry['jumpto']
        jumpto_new = entry['jumpto_new']
        if addr == addr_new and jumpto == jumpto_new: continue
        print(f"rebuild addr 0x{addr:x}->0x{addr_new:x}," 
            f"jumpto 0x{jumpto:x}->0x{jumpto_new:x}")
        data[addr_new: addr_new+4] = int.to_bytes(
            jumpto_new, 4, 'little', signed=False)
    if outpath!="":
        with open(outpath, 'wb') as fp:
            fp.write(data)
    
    return data

def debug():
    pass

def main():
    if len(sys.argv) < 3:
        print("advhd_ws2 e inpath [outpath]")
        print("advhd_ws2 i inpath orgpath [outpath]")
        return
    if sys.argv[1].lower() == 'e':
        outpath = sys.argv[3] if len(sys.argv) > 3 else "out.txt"
        export_ws2(sys.argv[2], outpath)
    elif sys.argv[1].lower() == 'i':
        outpath = sys.argv[4] if len(sys.argv) > 4 else "out.ws2"
        import_ws2(sys.argv[2], sys.argv[3], outpath)
    else: raise ValueError(f"unknow format {sys.argv[1]}")

if __name__ == '__main__':
    # debug()
    main()
    pass

"""
history:
v0.1, initial version for BlackishHouse
v0.2, support 華は短し、踊れよ乙女 (1.9.9.9)
"""