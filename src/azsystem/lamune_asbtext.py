"""
This is for parseing asb opcode
import text to decrypted asb file with ftext, 
including fix the problem
    v0.2, developed by devseed
"""

import sys
import codecs
import re
import struct

def read_format_text(inpath, only_text=False):
    """
    text dict is as {'addr':, 'size':, 'text':}
    :param: inpath can be path, or lines_text[] 
    :return: ftexts1[]: text dict array in '○' line, 
             ftexts2[]: text dict array in '●' line
    """
    ftexts1, ftexts2 = [], []
    if type(inpath) == str: 
        with codecs.open(inpath, 'r', 'utf-8') as fp: 
            lines_text = fp.readlines()
    else: lines_text = inpath

    if only_text == True: # This is used for merge_text
        re_line1 = re.compile(r"^○(.+?)○[ ](.*)")
        re_line2 = re.compile(r"^●(.+?)●[ ](.*)")
        for line in lines_text:
            line = line.strip("\n")
            m = re_line1.match(line)
            if m is not None:
                ftexts1.append({'addr':0,'size':0,'text': m.group(2)})
            m = re_line2.match(line)
            if m is not None:
                ftexts2.append({'addr':0,'size':0,'text': m.group(2)})
    else:
        re_line1 = re.compile(r"^○(\d*)\|(.*)\|(.*)○[ ](.*)")
        re_line2 = re.compile(r"^●(\d*)\|(.*)\|(.*)●[ ](.*)")
        for line in lines_text:
            line = line.strip("\n")
            m = re_line1.match(line)
            if m is not None:
                ftexts1.append({'addr':int(m.group(2),16),
                                'size':int(m.group(3),16),'text': m.group(4)})
            m = re_line2.match(line)
            if m is not None:
                ftexts2.append({'addr':int(m.group(2),16),
                                'size':int(m.group(3),16),'text': m.group(4)})
    return ftexts1, ftexts2

def save_tbl(tbl, outpath="out.tbl", encoding='utf-8'):
    with codecs.open(outpath, "w", encoding='utf-8') as fp:
        for charcode, c in tbl:
            charcode_str = ""
            for d in charcode:
                charcode_str += f"{d:02X}"
            fp.writelines("{:s}={:s}\n".format(charcode_str, c))
        print("tbl with " + str(len(tbl)) + " items saved to " + outpath)

# for exe utf16 text
def generate_sjisunicode(outpath=r"", index_empty=None, fullsjis=True):
    tbl = []
    for low in range(0x20, 0x7f): # asci
        charcode = struct.pack('<B', low)
        c = charcode.decode('sjis')
        tbl.append((c.encode('utf-16-le'), c))
    
    for high in range(0x81, 0xa0): # 0x81-0x9F
        for low in range(0x40, 0xfd):
            if low==0x7f: continue
            charcode = struct.pack('<BB', high, low)
            try:
                c = charcode.decode('sjis')
                tbl.append((c.encode('utf-16-le'), c))
            except  UnicodeDecodeError:
                c = '・'           
                if index_empty!=None:
                    index_empty.append(len(tbl))
    
    if fullsjis is True: end = 0xf0
    else: end =  0xeb
    for high in range(0xe0, end): # 0xE0-0xEF, sometimes 0xE0~-0xEA
        for low in range(0x40, 0xfd):
            if low==0x7f: continue
            charcode = struct.pack('<BB', high, low)
            try:
                c = charcode.decode('sjis')
                tbl.append((charcode, c))
            except  UnicodeDecodeError:
                c = '・'           
                if index_empty!=None:
                    index_empty.append(len(tbl))
        
    if outpath!="": save_tbl(tbl, outpath)
    print("sjis tbl with " + str(len(tbl)) + " generated!")
    return tbl

def parse_asb(asbdata, show=True):
    i = 0
    opcodes = []
    while i< len(asbdata):
        opcode = dict()
        opcode['addr'] = i
        opcode['optype'], opcode['oplen'] = struct.unpack('<II', asbdata[i:i+8])
        opcode['payload'] = asbdata[i+8: i+ opcode['oplen']]
        i += opcode['oplen']
        opcodes.append(opcode)
        if show:
            print(len(opcodes), hex(opcode['addr']),
                hex(opcode['optype']), hex(opcode['oplen']), 
                [hex(x) for x in opcode['payload'][0:0x10]])
    return opcodes

def import_text(ftextpath, asbpath, 
    outpath="out.asb"):
    ftexts1, ftexts2 = read_format_text(ftextpath)

    with open(asbpath, "rb") as fp:
        asbdata_old = fp.read()
        asbdata = bytearray(asbdata_old)

    # import chs text
    shift = 0
    for ftext in ftexts2:
        # print(ftext['text'])
        text = ftext['text']
        text = text.replace('〜', '') # 0x301c
        text = text.replace('・', '') # 0x30fb
        text = text.replace('♪', '')  # 0x266a
        text = text.replace('−', '')  # 0x2212
        text = text.replace('･', '')  # 0xff65
        text = text.replace('､', '')  # 0xff64
        text = text.replace('ﾟ', '')  # 0xff9f
        text = text.replace('⇒', '')  # 0x21d2
        text = text.replace('　', '')
        text = text.replace('[', '') # because this makes sjis crash
        text = text.replace(']', '')

        gbkdata = text.encode('gbk')
        addr = ftext['addr'] + shift
        size = ftext['size']
        oplen_addr = asbdata.rfind(b'\x00' * 0x8, 0, addr) - 0xc
        inclen = len(gbkdata) - size

        if 0 and inclen<=0:
            asbdata[addr: addr+len(gbkdata)] = gbkdata
            padding_byte = b'\x20'
            asbdata[addr+len(gbkdata): addr+size] = padding_byte * (size-len(gbkdata))
        else:
            asbdata[addr: addr+size] = gbkdata
            oplen = int.from_bytes(asbdata[oplen_addr: oplen_addr+2], 'little', signed=False)
            asbdata[oplen_addr: oplen_addr+2] = int.to_bytes(oplen+inclen, 2, 'little', signed=False);
            shift += inclen

    # fix jmp opcode addr
    for pattern in [b'\x0b\x00\x00\x00\x18\x00\x00\x00', 
        b'\x0a\x00\x00\x00\x1c\x00\x00\x00']:
        offset = 0
        offset_old = 0
        while True:
            offset = asbdata.find(pattern, offset)
            offset_old = asbdata_old.find(pattern, offset_old)
            if offset==-1 or offset_old==-1: break
            shift = offset - offset_old
            addr = offset + 0x8
            addrjmp = int.from_bytes(asbdata[addr: addr+0x4], 'little', signed=False)
            asbdata[addr: addr+0x4] = int.to_bytes(addrjmp+shift, 4, 'little', signed=False)
            # print(f"fix 0b jmp: at 0x{addr:06X}, 0x{addrjmp:06X}->0x{addrjmp+shift:06X}")
            offset += 0x18
            offset_old += 0x18

    with open(outpath, "wb") as fp:
        fp.write(asbdata)

    return asbdata

def main():
    if len(sys.argv) < 4:
        print("azsystem_text i ftextpath asbpath [rebuildpath]")
    if sys.argv[1].lower() == 'i':
        import_text(sys.argv[2], sys.argv[3], sys.argv[4])
    else:
        raise NotImplementedError()
    pass

def debug():
    # import_text("./build/intermediate/scenario_text/00plorogue.asb.txt", "./build/intermediate/scenario_dec/00plorogue.asb")
    # generate_sjisunicode("./build/sjisutf16.tbl")

    with open("./build/intermediate/scenario_dec/0nana_01.asb", 'rb') as fp:
        asbdata = fp.read()
    opcodes = parse_asb(asbdata)
    pass

if __name__ == "__main__":
    main()
    #debug()
    pass