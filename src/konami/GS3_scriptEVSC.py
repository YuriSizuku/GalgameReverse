"""
A tool to parse EVSC opcode, export or import text
for psp game  ときめきメモリアル Girl's Side 3rd Story
    v0.2.1, developed by devseeds
"""

import os
import sys
import re
import codecs
import struct
from io import BytesIO

sys.path.append(r".\..\..\util\script")
try:
    import zzbintext as bintext
except:
    import bintext

def print_evsc(evsc):
    pass

# evsc functions
def parse_evsc(data):
    # parse header
    header = {
    'magic': data[0:0x8],
    'header_size':int.from_bytes(data[0x8:0xc],'little',signed=False),
    'content_offset':int.from_bytes(data[0xc:0x10],'little',signed=False),
    'evsc_size1': int.from_bytes(data[0x10:0x14],'little',signed=False),
    'evsc_size2': int.from_bytes(data[0x14:0x18],'little',signed=False),
    'unknow1': int.from_bytes(data[0x18:0x1c],'little',signed=False)
    }

    # parse opcodes
    opcodes = []
    for i in range(header['header_size'], header['content_offset'], 8):
        optype, opnum = struct.unpack("<II", data[i: i+8])
        opcodes.append({"optype": optype, "opnum": opnum})

    evsc = {
        'header': header,
        'opcodes': opcodes,
        'content': data[header['content_offset']:],
    }
    return evsc

def export_evsctext(evscpath, outpath=""):
    ftexts = []
    with open(evscpath, "rb") as fp:
        data = fp.read()
    evsc = parse_evsc(data)
    if evsc['header']['magic']!=b'EVSC3.00':
        print(f"skip {evscpath} as no evsc file")
        return 
    
    content_offset = evsc['header']['content_offset']
    for opcode in evsc['opcodes']:
        if opcode['optype']==0xffffff03:
            offset = opcode['opnum']
            i = offset
            while True:
                if i >= len(evsc['content']):
                    break
                if evsc['content'][i] == 0 and evsc['content'][i+1] == 0:
                    break
                i += 2
            ccidx = evsc['content'].find(bytes([0xcc]*16), offset)
            if ccidx < 0: ccidx = len(evsc['content'])
            if ccidx - offset <= 8: continue
            try:
                text = evsc['content'][offset: i].decode('utf-16-le')
                text = text.replace('\r', '[\\r]').replace('\n', '[\\n]')
                flagcjk = False
                for c in text:
                    if bintext.isCjk(c):
                        flagcjk = True
                if not flagcjk: continue
                ftexts.append({
                    'addr': content_offset + offset, 
                    'size': i - offset,
                    'text': text
                })
                # print(text)
            except :
                pass
           
    if outpath!="":
        bintext.write_format_text(outpath, ftexts, ftexts)
    return ftexts

def import_evsctext(evscpath, ftextpath, outpath=""):
    with open(evscpath, "rb") as fp:
        data = bytearray(fp.read())
    evsc = parse_evsc(data)
    header = evsc['header']
    opcodes = evsc['opcodes']
    content = evsc['content']
    
    _, ftexts = bintext.read_format_text(ftextpath)
    ftexts.sort(key=lambda x: x['addr'])
    
    # insert text and fix the opcode pointer offset 
    shift = 0
    jump_table = []
    for i, opcode in enumerate(opcodes):
        if opcode['optype']==0xffffff03:
            offset = opcode['opnum']
            jump_table.append({'addr': i, 
                'addr_new': i, 
                'jumpto': offset, 
                'jumpto_new': offset})

    for ftext in ftexts:
        if ftext['addr'] > len(data):
            raise ValueError(f"addr out of data, {ftext['addr']:x}>{len(data):x}")
        _addr = ftext['addr'] - header['content_offset']
        _size = ftext['size']
        _text = ftext['text'].replace('[\\r]', '\r').replace('[\\n]', '\n')
        _textbytes = _text.encode('utf-16-le')
        _sizerebuid = len(_textbytes)
        
        if  _sizerebuid <= _size:
            _textbytes += b'\x20\x00' * ((_size - _sizerebuid) // 2)
            if len(_textbytes)!= _size:
                raise ValueError(f"_textbytes buffer {len(_textbytes):x}!= {_size:x}")
        else: # for 0x4 align
            _end = _addr + shift + _size
            while _end < len(content): 
                if content[_end]==0 and content[_end+1]==0: 
                    _end += 2
                else:
                    break
            _end += _sizerebuid - _size
            if _end % 4: 
                _textbytes += b'\x00'*(4 - _end%4)

        content[_addr+shift: _addr+shift+_size] = _textbytes
        if len(_textbytes) - _size > 0:
            shift += len(_textbytes) - _size
            for t in jump_table:
                if t['jumpto'] > _addr:
                    t['jumpto_new'] = t['jumpto'] + shift

    for t in jump_table:
        opcodes[t['addr']]['opnum'] = t['jumpto_new']
    
    # adjust header
    header['evsc_size1'] += shift
    header['evsc_size2'] += shift

    # write header
    _bufio = BytesIO()
    _bufio.write(header['magic'])
    _bufio.write(int.to_bytes(header['header_size'], 4, 'little'))
    _bufio.write(int.to_bytes(header['content_offset'], 4, 'little'))
    _bufio.write(int.to_bytes(header['evsc_size1'], 4, 'little'))
    _bufio.write(int.to_bytes(header['evsc_size2'], 4, 'little'))
    _bufio.write(int.to_bytes(header['unknow1'], 4, 'little'))

    # write opcode
    if _bufio.tell() != header['header_size']:
        raise ValueError(f"write opcode position wrong, \
            { _bufio.tell():x}!={header['header_size']:x}")
    for opcode in opcodes:
        _bufio.write(struct.pack('<II', 
            opcode['optype'], opcode['opnum']))

    # write content
    if _bufio.tell() != header['content_offset']:
        raise ValueError(f"write content position wrong, \
            { _bufio.tell():x}!={header['content_offset']:x}")
    _bufio.write(content)
    if _bufio.tell() != header['evsc_size1']:
        raise ValueError(f"write evsc size wrong, \
            { _bufio.tell():x}!={header['evsc_size1']:x}")

    if outpath!="":
        with open(outpath, "wb") as fp:
            fp.write(_bufio.getbuffer())
    return _bufio.getbuffer()

def debug():
    evscpath = r"D:\Make\Reverse\TokimekiMemorialGS3_psp\test\script_test\(0001)_A02_01_000.evd.decompressed"
    ftextpath = r"D:\Make\Reverse\TokimekiMemorialGS3_psp\intermediate\script_ftext\(0001)_A02_01_000.evd.txt"

    # test parse
    with open(evscpath, "rb") as fp:
        data = fp.read()
    evsc = parse_evsc(data)

    # test import
    import_evsctext(evscpath, ftextpath, "out.bin")

    # test export
    export_evsctext("out.bin", "out.txt")

def main():
    if len(sys.argv) < 3:
        print("GS3_scriptEVSC e(export) inpath [outpath]")
        print("GS3_scriptEVSC i(import) inpath ftextpath [outpath]")
        return
    inpath = sys.argv[2]
    if sys.argv[1].lower() == 'e': 
        outpath = sys.argv[3] if len(sys.argv) >= 4 else 'out'
        export_evsctext(inpath, outpath)
    elif sys.argv[1].lower() == 'i': 
        outpath = sys.argv[4] if len(sys.argv) >= 5 else 'out'
        import_evsctext(inpath, sys.argv[3], outpath)
    else: raise ValueError(f"{sys.argv[1]} not support!")

if __name__ == "__main__":
    #debug()
    main()
    pass

"""
history:
v0.1, initial version, export text by search [0xcc]*16
v0.2, export text by the pointer, add import function support longer text
V0.2.1, fix the text 0x4 align problem
"""