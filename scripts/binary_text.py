 # -*- coding: utf-8 -*-
import os
import struct
import re
import codecs
import argparse
from io import StringIO, BytesIO

"""
A binary text tool for text exporting and importing, checking 

v0.1 initial version with utf-8 support
v0.2 added tbl and decodetbl, encodetbl, check with tbl
v0.3 added extractsjis, extract by tbl or arbitary extract implement, patch using tbl
v0.3.1 added punctuation cjk, added try in decode

"""

def isCjk(c): 
    ranges = [
            {"from": ord(u"\u2000"), "to": ord(u"\u206f")},         # punctuation
            {"from": ord(u"\u3000"), "to": ord(u"\u303f")},         # punctuation cjk
            {"from": ord(u"\u3300"), "to": ord(u"\u33ff")},         # compatibility ideographs
            {"from": ord(u"\ufe30"), "to": ord(u"\ufe4f")},         # compatibility ideographs
            {"from": ord(u"\uf900"), "to": ord(u"\ufaff")},         # compatibility ideographs
            {"from": ord(u"\U0002F800"), "to": ord(u"\U0002fa1f")}, # compatibility ideographs
            {'from': ord(u'\u3040'), 'to': ord(u'\u309f')},         # Japanese Hiragana
            {"from": ord(u"\u30a0"), "to": ord(u"\u30ff")},         # Japanese Katakana
            {"from": ord(u"\u2e80"), "to": ord(u"\u2eff")},         # cjk radicals supplement
            {"from": ord(u"\u4e00"), "to": ord(u"\u9fff")},
            {"from": ord(u"\u3400"), "to": ord(u"\u4dbf")},
            {"from": ord(u"\U00020000"), "to": ord(u"\U0002a6df")},
            {"from": ord(u"\U0002a700"), "to": ord(u"\U0002b73f")},
            {"from": ord(u"\U0002b740"), "to": ord(u"\U0002b81f")},
            {"from": ord(u"\U0002b820"), "to": ord(u"\U0002ceaf")}  # included as of Unicode 8.0  
            ]
    return any([range["from"] <= ord(c) <= range["to"] for range in ranges])

def isText(data, encoding="utf-8"):
    try:
        data.decode(encoding)
    except UnicodeDecodeError:
        return False
    else: return True

def load_tbl(inpath, encoding='utf-8'):
    """
    :param inpath:tbl file format "code(XXXX) = utf-8 charcode", the sequence is the same as the text
    :return: [(charcode, charstr)]
    """
    tbl = []
    with codecs.open(inpath, 'r', encoding=encoding) as fp:
        re_line = re.compile(r'([0-9|A-F|a-f]*)=(\S|\s)$')
        while True:
            line = fp.readline()
            if not line : break
            m = re_line.match(line)
            if m is not None:
                d = int(m.group(1), 16)
                if d<0xff:
                    charcode = struct.pack("<B", d)
                elif d>0xff and d<0xffff:
                    charcode = struct.pack(">H", d)
                else:
                    charcode = struct.pack(">BBB", d>>16, (d>>8)&0xff, d&0xff)
                #print(m.group(1), m.group(2), d)
                c = m.group(2)
                tbl.append((charcode, c))
    print(inpath + " with " + str(len(tbl)) +" loaded!")
    return tbl

def encodetbl(text, tbl):
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

def decodetbl(data, tbl, maxlen=3):
    """
     decoding the data by tbl
    :return: the decoded text in python string
    """
    text = StringIO()
    i = 0
    while i<len(data):
        flag =False
        for n in range(1, maxlen+1):
            buf = data[i:i+n]
            for j in range(len(tbl)):
                if buf == tbl[j][0]:
                    text.write(tbl[j][1])
                    flag = True
                    break
            if flag: break
        
        i+=n
        if flag is False:
            print("Decodingtbl failed at "+str(1) +" "+ str(buf) )
            return None
    return text.getvalue()

def extract_text_utf8 (data, min_len=6):
    addrs, texts = [], []
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
                        texts.append(data[start:i])
                    start = -1
            i += 1
        else:  
            if isText(data[i:i+n+1], 'utf-8'):
                if start == -1:
                    start = i
                i += n+1
            else:
                if start != -1:
                    if i - start >= min_len:
                        addrs.append(start)
                        texts.append(data[start:i])
                    start = -1
                i += 1
    return addrs, texts

def extract_text_sjis(data, min_len=4):
    addrs, texts = [], []

    i = 0
    start = -1
    while i<len(data):
        flag_stop = False
        c1 = struct.unpack('<B', data[i:i+1])[0]
        if (c1 >= 0x20 and c1 <= 0x7f) or (c1 >= 0xa1 and c1 <= 0xdf): # asci
            if start == -1: start = i
            i+=1
        elif (c1 >= 0x81 and c1 <= 0x9f) or (c1 >= 0xe0 and c1 <= 0xef): # sjis
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
                    texts.append(data[start:i])
                start = -1
            i += 1
        else:
            if start == -1:
                start = i

    return addrs, texts

def extract_text_tbl(data, tbl, min_len=4): 
    """
    :param tbl: the customized charcode mapping to encoding charcode
    :return: All the extracted text is in utf-8
    """
    addrs, texts = [], []
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
                    texts.append(data[start:i])
                start = -1
            i+=1
        
    return addrs, texts

def patch_text(data, addrs, sizes, texts, encoding = 'utf-8', tbl=None):
    """
    :param encoding: the encoding of the original binary file if not using tbl
    """
    for _, (addr, text, size) in enumerate(zip(addrs, texts, sizes)):
        data[addr:addr+size] = bytearray(size)
        text = text.replace(r'[\n]', '\n')
        text = text.replace(r'[\r]', '\r')
        if tbl:
            buf = encodetbl(text, tbl)
        else:
            buf = text.encode(encoding)
        if len(buf) <= size : 
            size = len(buf)
        else: 
            print("at 0x%06X, %d bytes is lager than %d bytes!"%(addr, size, len(buf)))
        data[addr:addr+size] = buf[0:size]
        print("at 0x%06X, %d bytes replaced!"%(addr, size))
    return data
        

def check_text(textpath, outpath="check.txt", encoding="utf-8", tblpath=""):
    """
    checking if the text length or mapping to customized charcode valid
    :param encoding: the encoding of textpath
    :param tbl: the customized charcode mapping to encoding charcode, tbl must be in utf-8
    """
    if tblpath!="":
        tbl = load_tbl(tblpath)

    idxs, addrs, sizes, texts = [], [], [], []
    with codecs.open(textpath, 'r', 'utf-8') as fp:
        lines_text = fp.readlines()
        re_line1 = re.compile(r"○(\d*)\|(.*)\|(.*)○[ ](.*)")
        re_line2 = re.compile(r"●(\d*)\|(.*)\|(.*)●[ ](.*)")
        for _, line in enumerate(lines_text):
            line = line.strip("\n")
            m = re_line1.match(line)
            if m is not None:
                sizes.append(int(m.group(3), 16))
            m = re_line2.match(line)
            if m is not None:
                idxs.append(int(m.group(1)))
                addrs.append(int(m.group(2), 16))
                texts.append(m.group(4))

    with codecs.open(outpath, 'w', 'utf-8') as fp:
        for i in range(len(sizes)):
            err_str = ""
            if tbl:
                for j, c in enumerate(texts[i]):
                    if encodetbl(c, tbl) is None:
                        err_str+= "{}({:d}), ".format(c, j)
                if err_str!="":
                    line = "{}  {:06X}  {}".format(idxs[i], addrs[i], err_str[:-2])
                    print(line)
                    fp.write(line+"\n")

            if  err_str=="":
                text_len = len(encodetbl(texts[i], tbl)) if tbl else len(texts[i].encode(encoding))
                if text_len > sizes[i]:
                    line = "{}  {:06X}  {:d} > {:d}".format(idxs[i], addrs[i], text_len, sizes[i])
                    print(line)
                    fp.write(line+"\n")

def merge_text(inpath1, inpath2, outpath):
    """
    merge the '○' line in inpath2, '●' line in inpath2, to outpath
    """
    addrs1, sizes1, texts1 = [], [], []
    with codecs.open(inpath1, 'r', 'utf-8') as fp:
        lines_text = fp.readlines()
        re_line = re.compile(r"○(\d*)\|(.*)\|(.*)○[ ](.*)")
        for line in lines_text:
            line = line.strip("\n")
            m = re_line.match(line)
            if m is not None:
                addrs1.append(int(m.group(2), 16))
                sizes1.append(int(m.group(3), 16))
                texts1.append(m.group(4))

    addrs2, sizes2, texts2 = [], [], []
    with codecs.open(inpath2, 'r', 'utf-8') as fp:
        lines_text = fp.readlines()
        re_line = re.compile(r"●(\d*)\|(.*)\|(.*)●[ ](.*)")
        for line in lines_text:
            line = line.strip("\n")
            m = re_line.match(line)
            if m is not None:
                addrs2.append(int(m.group(2), 16))
                sizes2.append(int(m.group(3), 16))
                texts2.append(m.group(4))
    
    with codecs.open(outpath, "w",'utf-8') as fp:
        for i in range(len(addrs1)):
            addr = addrs1[i]
            size = sizes1[i]
            text1 = texts1[i]
            text2 = texts2[i]
            fp.write("○{num:04d}|{addr:06X}|{size:03X}○ {text}\n"
                .format(num=i, addr=addr, size=size, text=text1 ))
            fp.write("●{num:04d}|{addr:06X}|{size:03X}● {text}\n\n"
                .format(num=i, addr=addr, size=size, text=text2 ))
            print("at 0x%06X %d bytes merged" % (addr, size))
        print("merged text done! in " +  outpath)
        

def extract_text_file(inpath, outpath="out.txt", encoding = 'utf-8', tblpath="", min_len=6, has_cjk=True, f_extract=None):
    """
    export all the text to txt file in utf-8
    :param encoding: the encoding to the inpath, if tbl is None
    :param tbl:cuntom carcode, if not none, encoding param is the custom's
    """
    with open(inpath, "rb") as fp:
        data = fp.read()
        if tblpath!="" :
            tbl = load_tbl(tblpath, encoding=encoding) 
        else: tbl = None
        if f_extract:
            addrs, texts = f_extract(data, tbl)
        else:
            if tblpath!="" :
                addrs, texts = extract_text_tbl(data, tbl, min_len=min_len)
            elif encoding =="utf-8" :
                addrs, texts = extract_text_utf8(data, min_len=min_len)
            elif encoding == "sjis" or  encoding == "shift-jis":
                addrs, texts = extract_text_sjis(data, min_len=min_len)
            else: 
                print("Invalid encoding type!")
                return None

        with codecs.open(outpath, "w", 'utf-8') as fp2:
            for i, (addr, text) in enumerate(zip(addrs, texts)):
                size = len(text)
                if tbl is  None:
                    try:
                        text = text.decode(encoding)
                    except UnicodeDecodeError as e:
                        print("%s at %05d %06X"%(e, i, addr))
                        continue
                else: 
                    text = decodetbl(text, tbl)
                text = text.replace('\n', r'[\n]')
                text = text.replace('\r', r'[\r]')

                if has_cjk:
                    flag = False
                    for c in text:
                        if isCjk(c):
                            flag = True
                            break
                    if flag is False: continue

                fp2.write("○{num:05d}|{addr:06X}|{size:03X}○ {text}\n"
                    .format(num=i, addr=addr, size=size, text=text ))
                fp2.write("●{num:05d}|{addr:06X}|{size:03X}● {text}\n\n"
                    .format(num=i, addr=addr, size=size, text=text ))
                print("at 0x%06X %d bytes extraced" % (addr, size))
            print("extracted text done! in " +  outpath)
            
def patch_text_file(textpath, insertpath, outpath="out.bin", encoding = 'utf-8', tblpath="", f_encrypt=None, f_patch_text=None):
    """
    import the text in textpath to insertpath, make the imported file as outpath
    :param encoding: the encoding of the insertpath, or custom tbl's if not None
    """
    addrs, sizes, texts = [], [], []
    with codecs.open(textpath, 'r', 'utf-8') as fp:
        lines_text = fp.readlines()
        re_line = re.compile(r"●(\d*)\|(.*)\|(.*)●[ ](.*)")
        for line in lines_text:
            line = line.strip("\n")
            m = re_line.match(line)
            if m is not None:
                addrs.append(int(m.group(2), 16))
                sizes.append(int(m.group(3), 16))
                texts.append(m.group(4))

    with open(insertpath, "rb") as fp:
        data = bytearray(fp.read())
        if f_encrypt: 
            data = f_encrypt(data)
        tbl = None if tblpath=="" else load_tbl(tblpath, encoding=encoding)
        if f_patch_text:
            data = f_patch_text(data, addrs, sizes, texts, tbl)
        else:
            data = patch_text(data, addrs, sizes, texts, encoding=encoding, tbl=tbl)
    
    with open(outpath, "wb") as fp:
        fp.write(data)

def main():
    parser = argparse.ArgumentParser(description="binary text tool v0.3.1 by devseed")
    group = parser.add_mutually_exclusive_group()
    group.add_argument('-p', '--patch', type=str, help="patch the extracted text into inpath")
    group.add_argument('-m','--merge', type=str, help="merge the line with '●' in this file to the input file")
    group.add_argument('-c', '--check', action="store_true", help="check if the text is valid")
    parser.add_argument('-o', '--outpath', type=str, default=r".\out")
    parser.add_argument('-e', '--encoding', type=str, default='utf-8')
    parser.add_argument('--min_len', type=int, default=6)
    parser.add_argument('--tbl', type=str, default="", help="custom charcode table")
    parser.add_argument('--has_cjk', action="store_true", help="extract the text with cjk only")
    parser.add_argument('inpath', type=str)
    args = parser.parse_args()
    if args.patch:
        patch_text_file(args.inpath, args.patch, args.outpath, encoding=args.encoding, tblpath=args.tbl)
    elif args.merge:
        merge_text(args.inpath, args.merge, args.outpath)
    elif args.check:
        check_text(args.inpath, args.outpath, encoding=args.encoding, tblpath=args.tbl)
    else:
        extract_text_file(args.inpath, args.outpath, encoding=args.encoding, tblpath=args.tbl, has_cjk=args.has_cjk)

if __name__ == "__main__":
    main()