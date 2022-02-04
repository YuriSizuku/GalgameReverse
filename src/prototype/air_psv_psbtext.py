 # -*- coding: utf-8 -*-
"""
    for exporting and importing text in psv air
    v0.3, developed by devseed
"""

import sys
import re
import codecs
import argparse

sys.path.append(r".\..\..\util\script")
try:
    import zzbintext as bintext
except:
    import bintext
    
def extract_text(data, min_len=2):
    addrs = []
    texts = []
    
    i = 0
    while i < len(data):
        # 02 00 length text
        # without 02 00 F0 00
        if data[i] == 2 and data[i+1] == 0:
            length = data[i+2]
            if length == 0 or data[i+3]==0:
                i+=3
                continue
            start = i+3
            flag = False
            for j in range(start, start+length):
                if data[j]==0:
                    flag = True
                    break
            if flag:
                i+=3
                continue
            if length >= min_len:
                addrs.append(start)
                texts.append(data[start:start+length])
            i = start+length+1
        else:
            i += 1
    return addrs, texts

def patch_text(data, addrs, sizes, texts, tbl):
    jump_table = []
    # search jump opcode
    for i in range(len(data)): 
        if (data[i] == 0x0d and data[i+1] == 0xa4) or \
            data[i] == 0xa3:
            type = int.from_bytes(data[i-8:i-4], byteorder='big')
            if type== 0xF0000501:
                # real jumpto addr is jumpto+0x410
                jumpto = int.from_bytes(data[i-4:i], byteorder='big')
                addr = i-4
                jump_table.append({'addr':addr, 'jumpto':jumpto, 'addr_new':0, 'jumpto_new': 0})
                print(str(hex(data[i])) + " jump find at" + str(jump_table[-1]))
    print(str(len(jump_table))+" has benn found!") 

    # patch text, it can be longer now...
    offset_inc = 0
    for _, (addr, text, _) in enumerate(zip(addrs, texts, sizes)):
        length = data[addr+offset_inc-1]
        buf = bintext.encode_tbl(text ,tbl)
        if buf==None:
            print(hex(addr), text, " error!") 
            continue
        if len(buf) >= length:
            data[addr+offset_inc-1] = len(buf) # 02 00 [length]
            data[addr+offset_inc-4] = data[addr+offset_inc-4] + len(buf) - length # F0 00 [length]
            data[addr+offset_inc:addr+offset_inc+length] = buf
            offset_inc += len(buf) - length
            if len(buf) > length:
                for item in jump_table:
                    if item['jumpto'] + 0x410 > addr:
                        item['jumpto_new'] = item['jumpto'] + offset_inc
                    if item['addr'] > addr:
                        item['addr_new'] = item['addr'] + offset_inc
        else:
            data[addr+offset_inc:addr+offset_inc+len(buf)] = buf
            data[addr+offset_inc+len(buf):addr+offset_inc+length] = (length-len(buf)) * b'\x20'
    
    # rebuild jump pointer
    for item in jump_table:
        if item['jumpto_new'] > 0:
            addr = item['addr_new']
            jumpto = item['jumpto_new']
            data[addr:addr+4] = jumpto.to_bytes(4, byteorder='big')
            print(str(item) + " pointer rebuilt!")

    return data

def extract_text_file(inpath, outpath="out.txt"):
    with open(inpath, "rb") as fp:
        data = fp.read()
        addrs, texts = extract_text(data)
        with codecs.open(outpath, "w", 'utf-8') as fp2:
            for i, (addr, text) in enumerate(zip(addrs, texts)):
                size = len(text)
                text = text.decode('sjis')
                text = text.replace('\n', r'[\n]')
                text = text.replace('\r', r'[\r]')
                
                count_cjk = 0
                for c in text:
                    if bintext.isCjk(c):
                        count_cjk += 1
                if(count_cjk>=1):
                    fp2.write("○{num:04d}|{addr:06X}|{size:03X}○ {text}\n"
                        .format(num=i, addr=addr, size=size, text=text ))
                    fp2.write("●{num:04d}|{addr:06X}|{size:03X}● {text}\n\n"
                        .format(num=i, addr=addr, size=size, text=text ))
                    print("at 0x%06X %d bytes extraced" % (addr, size))
        print("extracted text done! in " +  outpath)

def patch_text_file(textpath, insertpath, tblpath, outpath="out.bin", ):
    addrs, sizes, texts = [], [], []
    with codecs.open(textpath, 'r', 'utf-8') as fp:
        lines_text = fp.readlines()
        re_line = re.compile(r"^●(\d*)\|(.*)\|(.*)●[ ](.*)")
        for line in lines_text:
            line = line.strip("\n")
            m = re_line.match(line)
            if m is not None:
                addrs.append(int(m.group(2), 16))
                sizes.append(int(m.group(3), 16))
                texts.append(m.group(4))

    with open(insertpath, "rb") as fp:
        data = bytearray(fp.read())
        tbl =  bintext.load_tbl(tblpath)
        data = patch_text(data, addrs, sizes, texts, tbl=tbl)
    
    with open(outpath, "wb") as fp:
        fp.write(data)

def main():
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group()
    group.add_argument('-p', '--patch', type=str, help="patch the extracted text into inpath")
    parser.add_argument('-o', '--outpath', type=str, default=r".\out")
    parser.add_argument('-t', '--tbl', type=str, default="", help="custom charcode table")
    parser.add_argument('inpath', type=str)
    args = parser.parse_args()
    if args.patch:
        patch_text_file(args.inpath, args.patch, args.tbl, outpath=args.outpath)
    else:
        extract_text_file(args.inpath, outpath=args.outpath)

def debug():
    #extract_text_file(r"D:\MAKE\Reverse\Air_project\intermediate\psvscr\03_F5A4B1C.psb" )
    patch_text_file(r"D:\MAKE\Reverse\Air_project\intermediate\text\29_B3B9702.txt", r"D:\MAKE\Reverse\Air_project\intermediate\psvscr\29_B3B9702.psb", r"D:\MAKE\Reverse\Air_project\intermediate\airpsv.tbl", outpath=r"D:\MAKE\Reverse\Air_project\intermediate\rebuild\psvscr\29_B3B9702.psb")
    pass

if __name__ == "__main__":
    main()
    #debug()
    pass
