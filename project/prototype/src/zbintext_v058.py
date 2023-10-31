 # -*- coding: utf-8 -*-
"""
A binary text tool for text exporting and importing, checking
    v0.5.8 developed by devseed
"""

import re
import struct
import codecs
import argparse
from io import StringIO, BytesIO
from typing import Any, Callable, Tuple, Union, List, Dict
from unittest.mock import patch

# lib functions
def iscjk(c: bytes): 

    ranges = [
    {"from": ord(u"\u2000"), "to": ord(u"\u206f")}, # punctuation
    {"from": ord(u"\u3000"), "to": ord(u"\u303f")}, # punctuation cjk
    # compatibility ideographs
    {"from": ord(u"\u3300"), "to": ord(u"\u33ff")},
    {"from": ord(u"\ufe30"), "to": ord(u"\ufe4f")},
    {"from": ord(u"\uf900"), "to": ord(u"\ufaff")},
    {"from": ord(u"\uff00"), "to": ord(u"\uffef")}, # full-width punctuation
    {"from": ord(u"\U0002F800"), "to": ord(u"\U0002fa1f")}, 
    {'from': ord(u'\u3040'), 'to': ord(u'\u309f')},# Japanese Hiragana
    {"from": ord(u"\u30a0"), "to": ord(u"\u30ff")},# Japanese Katakana
    {"from": ord(u"\u2e80"), "to": ord(u"\u2eff")},# cjk radicals 
    {"from": ord(u"\u4e00"), "to": ord(u"\u9fff")},
    {"from": ord(u"\u3400"), "to": ord(u"\u4dbf")},
    {"from": ord(u"\U00020000"), "to": ord(u"\U0002a6df")},
    {"from": ord(u"\U0002a700"), "to": ord(u"\U0002b73f")},
    {"from": ord(u"\U0002b740"), "to": ord(u"\U0002b81f")},
    {"from": ord(u"\U0002b820"), "to": ord(u"\U0002ceaf")}
    ]
    return any(
        [range["from"] <= ord(c) <= range["to"] 
        for range in ranges])

def hascjk(t: bytes) -> bool:

    flag = False
    for c in t:
        if iscjk(c):
            flag = True
            break
    return flag

def istext(data: bytes, encoding="utf-8"):

    try:
        data.decode(encoding)
    except UnicodeDecodeError:
        return False
    else: return True

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

def load_tbl(inobj: Union[str, List[str]], 
    encoding='utf-8') ->  List[Tuple[bytes, str]]:
    """
    tbl file format "code(XXXX) = utf-8 charcode", 
        the sequence is the same as the text
    :param inobj: can be path, or lines_text[] 
    :return: [(charcode, charstr)]
    """

    tbl = []
    if type(inobj) == str: 
        with codecs.open(inobj, 'r', encoding=encoding) as fp: 
            lines = fp.readlines()
    else: lines = inobj

    re_line = re.compile(r'([0-9|A-F|a-f]*)=(\S|\s)$')
    for line in lines:
        line = line.rstrip('\n').rstrip('\r')
        if not line : break
        m = re_line.match(line)
        if m is not None:
            charcode = bytearray()
            for i in range(0, len(m.group(1)), 2):
                d = int(m.group(1)[i: i+2], 16)
                charcode += d.to_bytes(1, 'little') 
            c = m.group(2)
            tbl.append((charcode, c))
            
    return tbl

def encode_tbl(text: str, 
    tbl: List[Tuple[bytes, str]]) -> bytes:
    """
    encoding the text by tbl
    :param tbl: for example [(charcode, c),...], c is the str
    :return: the encoded bytesarray
    """

    data = BytesIO()
    for c in text:
        flag = False
        for i in range(len(tbl)):
            if tbl[i][1] == c:
                data.write(tbl[i][0])
                flag =True
                break
        if flag is False:
            print("Encodingtbl failed with "+ c + " in tbl")
            return None
    return data.getvalue()

def decode_tbl(data: bytes, 
    tbl: List[Tuple[bytes, str]], max_char_len=3) -> str:
    """
     decoding the data by tbl
    :return: the decoded text in python string
    """

    text = StringIO()
    i = 0
    while i<len(data):
        flag =False
        for n in range(1, max_char_len+1):
            buf = data[i:i+n]
            for j in range(len(tbl)):
                if buf == tbl[j][0]:
                    text.write(tbl[j][1])
                    flag = True
                    break
            if flag: break
        
        i+=n
        if flag is False:
            print("Decodingtbl failed at " + str(1) + " "+ str(buf) )
            return None
    return text.getvalue()

def extract_textutf8 (data, min_len=3) \
    -> Tuple[List[int], List[int]]:

    addrs, sizes = [], []
    utf8_lead_byte_to_count = []
    for i in range(256):
        utf8_lead_byte_to_count.append(1 + (i >= 0xe0) + (i >= 0xf0) if 0xbf < i < 0xf5 else 0)
    i = 0
    start = -1
    while i<len(data):
        lead = struct.unpack('<B', data[i:i+1])[0]
        n = utf8_lead_byte_to_count[lead]
        if n <= 0:
            if lead >= 0x20 and lead <= 0x7f:
                if start == -1: start = i
            else:
                if start != -1:
                    if i - start >= min_len:
                        addrs.append(start)
                        sizes.append(i-start)
                    start = -1
            i += 1
        else:  
            if istext(data[i:i+n+1], 'utf-8'):
                if start == -1:
                    start = i
                i += n+1
            else:
                if start != -1:
                    if i - start >= min_len:
                        addrs.append(start)
                        sizes.append(i-start)
                    start = -1
                i += 1
    return addrs, sizes

def extract_textsjis(data, min_len=2) \
    -> Tuple[List[int], List[int]]:

    addrs, sizes = [], []
    i = 0
    start = -1
    while i<len(data):
        flag_stop = False
        c1 = struct.unpack('<B', data[i:i+1])[0]
        if (c1 >= 0x20 and c1 <= 0x7f) or (c1 >= 0xa1 and c1 <= 0xdf): 
            # asci
            if start == -1: start = i
            i+=1
        elif (c1 >= 0x81 and c1 <= 0x9f) or (c1 >= 0xe0 and c1 <= 0xef): 
            # sjis
            if i+2>len(data): break
            c2 = struct.unpack('<B', data[i+1:i+2])[0]
            if (c2 >= 0x40 and c2 <= 0x7e) or (c2 >= 0x80 and c2 <= 0xfc): 
                if start == -1: start = i
                i+=2
            else:
                flag_stop = True
        else:
            flag_stop = True

        if flag_stop:
            if start != -1:
                if i - start >= min_len:
                    addrs.append(start)
                    sizes.append(i-start)
                start = -1
            i += 1
        else:
            if start == -1:
                start = i

    return addrs, sizes

def extract_textunicode(data, min_len=2) \
    -> Tuple[List[int], List[int]]:

    addrs, sizes = [], []
    i = 0
    start = -1 
    while i+1 < len(data):
        u1,  = struct.unpack('<H', data[i:i+2])
        if u1 < 0x20:
            if start != -1:
                if i-start >= min_len:
                    print("detected text in [{:X}:{:X}] through {:s}".format(start, i, "unicode"))
                    addrs.append(start)
                    sizes.append(i-start)
                start = -1
            i += 2
        elif u1 >= 0x20 and u1 <= 0x7f:
            if start == -1:  start = i
            i += 2
        else:
            c = data[i:i+2]
            if istext(c, encoding='utf-16'):
                if start == -1: start = i
                i += 2
            else:
                if start != -1:
                    if i-start >= min_len:
                        print("detected text in [{:X}:{:X}] through {:s}".format(start, i, "unicode"))
                        addrs.append(start)
                        sizes.append(i-start)
                    start = -1
                i += 2
    return addrs, sizes

def extract_texttbl(data, tbl: List[Tuple[bytes, str]], 
    min_len=2) -> Tuple[List[int], List[int]]: 
    """
    :param tbl: the customized charcode mapping to encoding charcode
    :return: all the extracted text is in utf-8
    """

    addrs, sizes = [], []
    i = 0
    start = -1 
    while i<len(data):
        c1 = struct.unpack('<B', data[i:i+1])[0]
        flag_find = False
        for charcode, _ in tbl:
            if c1==charcode[0]:
                n = len(charcode)
                if data[i:i+n] == charcode:
                    if start==-1: start=i
                    flag_find = True
                    i+=n
                    break

        if flag_find is False:
            if start != -1:
                if i-start >= min_len:
                    print("detected text in [{:X}:{:X}] through tbl".format(start, i))
                    addrs.append(start)
                    sizes.append(i-start)
                start = -1
            i += 1
        
    return addrs, sizes

def extract_textmultichar(data, encoding, 
    min_len=2) -> Tuple[List[int], List[int]]:
    """
    except unicode
    """

    addrs, sizes = [], []
    i = 0
    start = -1 
    while i<len(data):
        c1,  = struct.unpack('<B', data[i:i+1])
        if c1 < 0x20:
            if start != -1:
                if i-start >= min_len:
                    print("detected text in [{:X}:{:X}] through {:s}".format(start, i, encoding))
                    addrs.append(start)
                    sizes.append(i-start)
                start = -1
            i += 1
        elif c1 >= 0x20 and c1 <= 0x7f:
            if start == -1:  start = i
            i += 1
        else:
            c = data[i:i+2]
            if istext(c, encoding=encoding):
                if start == -1: start = i
                i += 2
            else:
                if start != -1:
                    if i-start >= min_len:
                        print("detected text in [{:X}:{:X}] through {:s}".format(start, i, encoding))
                        addrs.append(start)
                        sizes.append(i-start)
                    start = -1
                i += 1
    return addrs, sizes

def patch_text(orgdata: bytearray, 
    ftexts: List[Dict[str, Union[int, str]]],
    encoding='utf-8', tbl: List[Tuple[bytes, str]]=None, 
    can_longer=False, can_shorter=False, 
    align=1, is_copy=False, is_mute=False, 
    replace_map: Dict[str, str]=None, padding_bytes=b'\x00', 
    search_data=None, *, jump_table: Dict[str, int]=None, 
    f_extension: Callable[[str, Any], str]=
        lambda x, args: eval(x), fargs_extension=None, 
    f_adjust: Callable[[bytearray, bytes, 
        int, int, int, Any], None]=None, fargs_adjust=None
    ) -> bytes:
    """
    :param data: bytearray
    :param encoding: the encoding of the original binary file if no tbl
    :param replace_map: a dict for replaceing char, {'a': 'b'} 
    :param padding_bytes: paddings if rebuild text shorter
    :param search_data: get the bytes in search_data by addr, 
        and then search the pattern to replace

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
    _searchedset = set()
    ftexts.sort(key=lambda x: x['addr'])
    for _, ftext in enumerate(ftexts):
        addr, size, text = ftext['addr'], ftext['size'], ftext['text'] 
        
        # search the pattern by other data
        if search_data is not None:
            _bytes = search_data[addr+shift: addr+shift+size]
            addr = -1
            while True:
                addr = data.find(_bytes, addr+1)
                if addr not in _searchedset:
                    _searchedset.add(addr)
                    break
                if addr < 0: break 
        if addr < 0: continue
       
        # parse the patterns in text
        text = text.replace(r'[\n]', '\n')
        text = text.replace(r'[\r]', '\r')
        if replace_map is not None:
            for k, v in replace_map.items():
                text = text.replace(k, v)
        bufio = BytesIO()
        if text.find("{{") == -1:
            if tbl: bufio.write(encode_tbl(text, tbl))
            else: bufio.write(text.encode(encoding))
        else:
            start = 0
            while start + 2 < len(text):
                end = text.find('{{', start)
                if end < 0: break
                if tbl: bufio.write(encode_tbl(text[start: end], tbl))
                else: bufio.write(text[start: end].encode(encoding))
                start = end + 2
                end = text.find('}}', start)
                if end < 0: 
                    raise ValueError(
                        f"pattern not closed at {addr:x}, {text}")
                _bytes = f_extension(text[start:end], fargs_extension)
                bufio.write(_bytes)
                start = end + 2

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
        
# cli functions
def check_ftextobj(ftextobj: Union[str, List[str]], 
    outpath="check.txt", encoding="utf-8", 
    tblobj: Union[str, List[str]]="", 
    replace_map: Dict[str, str]=None) \
        -> List[Dict[str, Union[int, str]]]:
    """
    checking if the text length or mapping to customized charcode valid
    :param encoding: the encoding of textpath
    :param tbl: the customized charcode mapping to encoding charcode, 
    tbl must be in utf-8
    :return: {"addr":addr, "msg": msgtext}
    """

    if tblobj!="": tbl = load_tbl(tblobj, encoding)
    else: tbl = None
    _, ftexts = load_ftext(ftextobj)
    errors = []

    fp = None
    if outpath!="": fp = codecs.open(outpath, 'w', 'utf-8')
    for i, ftext in enumerate(ftexts):
        err_str = ""
        addr, size, text = ftext['addr'], ftext['size'], ftext['text'] 
        if replace_map is not None:
            for k, v in replace_map.items():
                text = text.replace(k, v)

        # check encoding 
        for j, c in enumerate(text):
            if tbl is not None:
                if encode_tbl(c, tbl) is None:
                    err_str+= "{}({:d}), ".format(c, j)
            else:
                try:
                    c.encode(encoding)
                except UnicodeEncodeError as e:
                    err_str+= "{}({:d}), ".format(c, j)

        if err_str!="":
            line = "{}  {:06X}  {}".format(i, addr, err_str[:-2])
            print(line)
            if fp: fp.write(line+"\n")

        # check length
        if  err_str == "":
            text_len = len(encode_tbl(text, tbl)) \
                if tbl else len(text.encode(encoding))
            if text_len > size:
                line = "{}  {:06X}  {:d} > {:d}"\
                    .format(i, addr, text_len, size)
                err_str += line
                print(line)
                if fp: fp.write(line + "\n")

        if len(err_str):
            errors.append({'addr': addr, 'msg': err_str})
    if fp: fp.close()
    return errors

def verify_ftextobj(ftextobj: Union[str, List[str]], 
    binobj: Union[str, bytes], outpath="verify.txt", 
    encoding="utf-8", tblobj: Union[str, List[str]]=""):
    """
    verify if the text matching origin binfile
    :param encoding: the encoding of textpath
    :param tbl: the customized charcode 
        mapping to encoding charcode, tbl must be in utf-8
    :return: {"addr":addr, "msg": msgtext}
    """

    if tblobj!="": tbl = load_tbl(tblobj, encoding)
    else: tbl = None

    ftexts, _ = load_ftext(ftextobj)
    if type(binobj) == str:
        with open(binobj, 'rb') as fp:
            data = fp.read()
    else: data = binobj
    errors = []
    
    fp = None
    if outpath!="": fp = codecs.open(outpath, 'w', 'utf-8')
    for i, ftext in enumerate(ftexts):
        err_str = ""
        addr, size, text = \
            ftext['addr'],ftext['size'],ftext['text'] 
        _text = None
        if tbl is not None:
            _text = decode_tbl(data[addr: addr+size], tbl)
        else: 
            try:
                _data = data[addr: addr+size]
                _text = _data.decode(encoding)
            except UnicodeDecodeError as e:
                print(e)
        if _text != text:
            err_str = f"{i}, {addr:06X}, {size:02X} {text} != {_text}"
            print(err_str)
            if fp: fp.write(err_str + "\n")
        if len(err_str):
            errors.append({'addr': addr, 'msg': err_str})
    if fp: fp.close()
    return errors
                    
def merge_ftextobj(ftextobj1: Union[str, List[str]], 
    ftextobj2: Union[str, List[str]], outpath: str=""):
    """
    merge the '○' line in inpath2, 
        '●' line in inpath2, to outpath
    :return: merged lines
    """

    ftexts1, _ = load_ftext(ftextobj1)
    _, ftexts2 = load_ftext(ftextobj2, only_text=True)
    lines = dump_ftext(ftexts1, ftexts2, outpath=outpath)
    return lines
        
def shift_ftextobj(ftextobj: Union[str, List[str]]
    , n, outpath: str=""):
    """
    shift all the addr by n
    :return: shift lines
    """
    ftexts1, ftexts2 = load_ftext(ftextobj)
    for ftext1, ftext2 in zip(ftexts1, ftexts2):
        ftext1['addr'] += n
        ftext2['addr'] += n
    lines = dump_ftext(ftexts1, ftexts2, outpath=outpath)
    return lines
            
def patch_ftextobj(ftextobj: Union[str, List[str]], 
    binobj: Union[str, bytes], outpath="out.bin", 
    encoding = 'utf-8', tblobj: Union[str, List[str]]="",
    can_longer=False, can_shorter=False, align=1,
    replace_map: Dict[str, str]=None,
    padding_bytes=b"\x00", searchobj: Union[str, bytes]="", 
    *, jump_table: Dict[str, int]=None, 
    f_extension: Callable[[str, Any], str]=
        lambda x, args: eval(x), fargs_extension=None, 
    f_adjust: Callable[[bytearray, bytes, 
        int, int, int, Any], None]=None, fargs_adjust=None
    ) -> bytes:
    """
    import the text in textpath to insertpath, make the imported file as outpath
    ftexts should always using encoding utf-8
    :param encoding: the encoding of the insertpath, 
        or custom tbl's if not None
    """

    _, ftexts2 = load_ftext(ftextobj)
    
    if type(binobj) == str:
        with open(binobj, 'rb') as fp:
            data = bytearray(fp.read())
    else: data = binobj
    
    if tblobj!="": tbl = load_tbl(tblobj, encoding)
    else: tbl = None
    search_data = None

    if type(searchobj) == str:
        if searchobj!="":
            with open(searchobj, 'rb') as fp:
                search_data = fp.read()
    elif type(searchobj)== bytes or type(searchobj)==bytearray:
        search_data = searchobj
    else: search_data = searchobj

    data = patch_text(data, ftexts2, 
        encoding=encoding, tbl=tbl, 
        can_longer=can_longer, can_shorter=can_shorter, align=align,
        replace_map=replace_map,padding_bytes=padding_bytes,
        search_data=search_data,jump_table=jump_table,
        f_extension=f_extension, fargs_extension=fargs_extension,
        f_adjust=f_adjust, fargs_adjust=fargs_adjust)
    
    if outpath!="":
        with open(outpath, "wb") as fp:
            fp.write(data)
    return data

def extract_ftextobj(binobj: Union[str, bytes], 
    outpath="out.txt", encoding='utf-8', 
    tblobj: Union[str, List[str]]="", 
    start_addr=0, end_addr=0, 
    min_len=2, has_cjk=True):
    """
    export all the text to txt file in utf-8
    :param encoding: the encoding to the inpath, 
        if tbl is None, or this will be tbl encoding
    :param tbl: cuntom charcode, if not none, 
        encoding param is the custom's
    :return: ftexts lines
    """

    if type(binobj) == str:
        with open(binobj, 'rb') as fp:
            data = fp.read()
    else: data = binobj

    if tblobj!="": tbl = load_tbl(tblobj, encoding)
    else: tbl = None
    if end_addr == 0: end_addr = len(data)
    print(f"size={len(data):x}, startaddr={start_addr:x}, endaddr={end_addr:x}")
   
    if tbl is not None:
        addrs, sizes = extract_texttbl(
            data[start_addr: end_addr], tbl, min_len=min_len)
    elif encoding =="utf-8" :
        addrs, sizes = extract_textutf8(
            data[start_addr: end_addr], min_len=min_len)
    elif encoding == "sjis":
        addrs, sizes = extract_textsjis(
            data[start_addr: end_addr], min_len=min_len)
    elif encoding == "unicode":
        addrs, sizes = extract_textunicode(
            data[start_addr: end_addr], min_len=min_len)
        encoding = 'utf-16'
    else: 
        addrs, sizes = extract_textmultichar(
            data[start_addr: end_addr], 
            encoding=encoding, min_len=min_len)
    addrs = list(map(lambda x: x + start_addr, addrs))

    ftexts = []
    for i,(addr, size) in enumerate(zip(addrs, sizes)):
        if tbl is None:
            try:
                text = data[addr: addr+size].decode(encoding)
            except UnicodeDecodeError as e:
                print("%s at %05d %06X"%(e, i, addr))
                continue
        else: 
            text = decode_tbl( data[addr: addr+size], tbl)
        text = text.replace('\n', r'[\n]')
        text = text.replace('\r', r'[\r]')
        if has_cjk and not hascjk(text): continue
        
        ftexts.append({'addr':addr, 'size':size, 'text':text})
        print("at 0x%06X %d bytes extraced" % (addr, size))

    lines = dump_ftext(ftexts, ftexts, outpath=outpath)
    print("extracted text done! in " +  outpath)
    return lines

def debug():
    pass

def main(cmdstr=None):
    parser = argparse.ArgumentParser(
        description="bintext v0.5.8, developed by devseed")
    
    # input and output
    parser.add_argument('inpath', type=str)
    parser.add_argument('-o', '--outpath', type=str, 
        default=r"./result.txt")
    
    # select method
    methodcfg = parser.add_mutually_exclusive_group()
    methodcfg.add_argument('-c', '--check', action='store_true', 
        help="check if the translate text is valid")
    methodcfg.add_argument('-v', '--verify', type=str, 
        help="verify if the origin text the same as dump")
    methodcfg.add_argument('-s', '--shift', type=int, 
        help="shift the addr with n")
    methodcfg.add_argument('-m','--merge', type=str,
        help="merge the line with '●' in this file to the inpath file")
    methodcfg.add_argument('-p', '--patch', type=str, 
        help="patch this path by the inpath text, binpath")
    
    #  util configure
    utilcfg = parser.add_argument_group(title="util config")
    utilcfg.add_argument('-e', '--encoding', 
        type=str, default='utf-8', 
        help="if using tbl, this encoding is for tbl")
    utilcfg.add_argument('--tbl', type=str, default="", 
        help="custom charcode table")
    utilcfg.add_argument('--replace_map', 
        type=str, default=[""], nargs='+', 
        help="replace the char in 'a:b' 'c:d' format")
   
    # extract configure
    extractcfg = parser.add_argument_group(title="extract config")
    extractcfg.add_argument('--start_addr', type=int,         
        default=0, help="extract text start with this addr")
    extractcfg.add_argument('--end_addr', type=int, 
        default=0, help="extract text end with this addr")
    extractcfg.add_argument('--min_len', type=int, default=2)
    extractcfg.add_argument('--has_cjk', action='store_true', 
        help="extract the text with cjk only")

    # patch configure
    pathchcfg = parser.add_argument_group(title="patch config")
    pathchcfg.add_argument('--can_longer', action='store_true', 
        help="inserted text can be longer than the original")
    pathchcfg.add_argument('--can_shorter', action='store_true', 
        help="inserted text can be longer than the original")
    pathchcfg.add_argument('--align', type=int, default=1, 
        help="the align number for patching, when --can_longer")
    pathchcfg.add_argument('--search_file', type=str, 
        default="", help="search the origin text for replace")
    pathchcfg.add_argument('--padding_bytes', 
        type=int, default=[0x20], nargs='+',
        help="padding char if import text shorter than origin")

    # parse args
    if cmdstr is None: args = parser.parse_args()
    else: args = parser.parse_args(cmdstr.split(' '))
    replace_map = dict()
    for t in args.replace_map:
        _t = t.split(':')
        if len(_t)<2: continue
        replace_map[_t[0]] = _t[1]
        
    if args.check:
        check_ftextobj(args.inpath, args.outpath, 
            encoding=args.encoding, tblobj=args.tbl,
            replace_map=replace_map)
    elif args.verify:
        verify_ftextobj(args.inpath, args.verify, args.outpath,   
            encoding=args.encoding, tblobj=args.tbl)
    elif args.shift:
        shift_ftextobj(args.inpath, args.shift, args.outpath)
    elif args.merge:
        merge_ftextobj(args.inpath, args.merge, args.outpath)
    elif args.patch:
        patch_ftextobj(args.inpath, args.patch, args.outpath, 
            encoding=args.encoding,  tblobj=args.tbl, 
            can_longer=args.can_longer,  can_shorter=args.can_shorter,
            align=args.align, replace_map=replace_map, 
            padding_bytes=bytes(args.padding_bytes),
            searchobj = args.search_file)
    else:
        extract_ftextobj(args.inpath, args.outpath, 
            encoding=args.encoding, tblobj=args.tbl, 
            start_addr=args.start_addr, end_addr=args.end_addr,
            has_cjk=args.has_cjk, min_len=args.min_len)

if __name__ == "__main__":
    # debug()
    main()
    pass

"""
history:
v0.1, initial version with utf-8 support
v0.2, added tbl and decodetbl, encodetbl, check with tbl
v0.3, added extractsjis, extract by tbl or arbitary extract implement, patch using tbl
v0.3.1, added punctuation cjk, added try in decode
v0.3.2, fixed patched error when short than origin 
v0.3.3, change the merge function with matching "●(.*)●[ ](.*)"
v0.4, add read_format_text, write_format_text, optimize the code structure
v0.4.1, fixed merge_text in this optimized the code structure
v0.4.2, remove useless callbacks, adjust default len, add arbitary encoding, add jump_table rebuild, 
v0.4.3, change the structure, write_format_text, read_format_text added line_texts mode
v0.4.4, adding padding char if text shorter than origin (in order with \x0d, \x0a, zeros will stop str), 
v0.4.5, fix the padding problem, --padding bytes 32 00
v0.5, add verify text, shift addr function
v0.5.1, fix the problem of other encoding tbl; read_format_text regex in lazy mode.
v0.5.2, add replace_map in patch_text
v0.5.3, add serach replace text mode by --search_file
v0.5.4, add extraxt --start, --end parameter
v0.5.5, add extract_unicode for 0x2 aligned unicode
v0.5.6, add typing hint and prepare read lines for pyscript in web
v0.5.7, add repalced map in check method, fix -e in check 
v0.5.8, add f_extension for {{}}, f_adjust in patch_text, and align for patch
"""