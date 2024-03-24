"""
export or import wsc text for willplus advhd, 
tested in AyakashiGohan (v1.0.1.0)
    v0.1, developed by devseed
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

# wsc functions
wscname_t = namedtuple("wscname_t", ['addr', 'size', 'text'])
wscoption_t = namedtuple("wscoption_t", ['addr', 'size', 'text', 'rawaddr', 'rawsize'])
wsctext_t = namedtuple("wsctext_t", ['addr', 'size', 'text'])

def export_wsc(inpath, outpath="out.txt", encoding='sjis'):
    with open(inpath, 'rb') as fp:
        data = bytearray(fp.read())

    entryids = [0]
    names: List[wscname_t] = []
    texts: List[wsctext_t] = []
    options: List[wscoption_t] = []

    # 41 [id 4] [text n] 00
    cur = 0
    pattern = b'\x41'
    while True:
        cur = data.find(pattern, cur)
        if cur < 0: break
        cur += len(pattern)
        entryid = int.from_bytes(
            data[cur: cur+4], 'little', signed=False)
        if entryid - max(entryids) > 0x1000:
            cur += 1
            continue
        addr = cur + 4
        size = data.find(b'\x00', addr) - addr
        try:
            text = data[addr: addr+size].decode(encoding)
            if size > 0: texts.append(wsctext_t(addr, size, text))
            cur = addr + size + 1
        except UnicodeDecodeError as e:
            cur += 1
            continue
        entryids.append(entryid)

    # 42 [id 4] 00 [name n] 00 [text n] 00
    cur = 0 
    pattern = b'\x42'
    while True:
        cur = data.find(pattern, cur)
        if cur < 0: break
        cur += len(pattern)
        entryid = int.from_bytes(
            data[cur: cur+4], 'little', signed=False)
        if entryid - max(entryids) > 0x1000 or data[cur+4]!=0:
            cur += 1
            continue
        addr = cur + 5
        size = data.find(b'\x00', addr) - addr
        try:
            text = data[addr: addr+size].decode(encoding)
            if size > 0: names.append(wscname_t(addr, size, text))
            cur = addr + size + 1
        except UnicodeDecodeError as e:
            cur += 1
            continue
        addr = cur
        size = data.find(b'\x00', addr) - addr
        try: 
            text = data[addr: addr+size].decode(encoding)
            if size > 0: texts.append(wsctext_t(addr, size, text))
            cur = addr + size + 1
        except UnicodeDecodeError as e:
            cur += 1
            continue
        entryids.append(entryid)

    # 03 00 00 00 00 02 [noption 2] 
	#   [id 2] [text n] 00 [hash 4] [file n] 00
    cur = 0
    pattern = b'\x03\x00\x00\x00\x00\x02'
    while True:
        cur = data.find(pattern, cur)
        if cur < 0: break
        cur += len(pattern)
        noption = int.from_bytes(
            data[cur: cur+2], 'little', signed=False)
        if noption > 5:
            cur += 1
            continue
        cur += 2
        for i in range(noption):
            rawaddr = cur 
            addr = cur + 2
            size = data.find(b'\x00', addr) - addr
            text = data[addr: addr+size].decode(encoding)
            rawsize = data.find(b'\x00', addr+size+5)  - rawaddr + 1
            options.append(wscoption_t(
                addr, size, text, rawaddr, rawsize))
            cur += rawsize
    
    # merge text to ftext
    ftexts = []
    ftexts.extend([{'addr': x.addr, 
        'size': x.size, 'text': x.text} for x in names]) 
    ftexts.extend([{'addr': x.addr, 
        'size': x.size, 'text': x.text} for x in texts \
            if x.addr not in [y['addr'] for y in ftexts]]) 
    ftexts.extend([{'addr': x.addr, 
        'size': x.size, 'text': x.text} for x in options]) 
    ftexts.sort(key=lambda x: x['addr'])
    if outpath!="":
        dump_ftext(ftexts, ftexts, outpath)

    return ftexts

def import_wsc(inpath, orgpath, outpath="out.ws2", encoding="gbk"):
    
    def _addjumpentry(data, addr):
        if addr > len(data): return None
        jumpto = int.from_bytes(data[addr: addr+4], 
            'little', signed=True)
        if jumpto > 0 and jumpto < len(data):
            return {'addr': addr, 'jumpto': jumpto, 
                'addr_new': addr, 'jumpto_new': jumpto}

    _, ftexts = load_ftext(inpath)
    with open(orgpath, 'rb') as fp:
        data = bytearray(fp.read())
    
    # make jump_table
    jump_table = []

    # import text
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
    export_wsc("./buildv1/intermediate/Rio/ASA_01.WSC")
    # import_wsc("./build/intermediate/Rio2_ftext/BZhal_03.ws2.txt", "./build/intermediate/Rio2/BZhal_03.ws2")
    pass

def main():
    if len(sys.argv) < 3:
        print("advhd_ws2 e inpath [outpath]")
        print("advhd_ws2 i inpath orgpath [outpath]")
        return
    if sys.argv[1].lower() == 'e':
        outpath = sys.argv[3] if len(sys.argv) > 3 else "out.txt"
        export_wsc(sys.argv[2], outpath)
    elif sys.argv[1].lower() == 'i':
        outpath = sys.argv[4] if len(sys.argv) > 4 else "out.ws2"
        import_wsc(sys.argv[2], sys.argv[3], outpath)
    else: raise ValueError(f"unknow format {sys.argv[1]}")

if __name__ == '__main__':
    # debug()
    main()
    pass