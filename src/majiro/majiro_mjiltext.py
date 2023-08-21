"""
majiro engine, mjil text export import   
  v0.1.1, developed by devseed
　the multi encoding annotation [[cp936]] is for mjotool2 modified by me

tested game: 
  そらいろ (ねこねこソフト) v1.1
  ルリのかさね ～いもうと物語り (ねこねこソフト)

See also,  
https://github.com/AtomCrafty/MajiroTools
https://github.com/trigger-segfault/majiro-py

"""

import re
import sys
import codecs
from collections import namedtuple 
from typing import Union, List, Dict

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

# mjil functions
mjil_pattern = re.compile(r'(\S+): (\S+)\s*(.+?)[\r\n]+')
mjil_optioncall_pattern = re.compile(r'\$57f252db \((\d+)\)')
mjil_t = namedtuple("mjil_t", ["addr", "opcode", "operand"])

def load_mjil(line) -> mjil_t:
    m = re.search(mjil_pattern, line)
    if m is None: return None
    addr = int(m.group(1), 16)
    opcode = m.group(2)
    operand = m.group(3)
    return mjil_t(addr, opcode, operand)

def export_mjiltext(inpath, outpath="out.txt"):
    with codecs.open(inpath, 'r', 'utf8') as fp:
        lines = fp.readlines()
    mjils = [load_mjil(line) for line in lines]
    mjils = list(filter(lambda x: x!=None, mjils))
    
    ftexts = []
    for i, mjil in enumerate(mjils):
        if mjil.opcode == "text": # normal text
            ftexts.append({"addr": mjil.addr, "size": 0, 
                "text": mjil.operand.strip('"')})
        elif mjil.opcode == "call": # option
            m = re.search(mjil_optioncall_pattern, mjil.operand)
            if m is None: continue
            n = int(m.group(1))
            for j in range(n-2):
                if mjils[i-n+j].opcode != "ldstr": continue
                ftexts.append({"addr": mjils[i-n+j].addr, "size": 0, 
                    "text": mjils[i-n+j].operand.strip('"')})
            
    return dump_ftext(ftexts, ftexts, outpath)

def import_mjiltext(inpath, orgpath, outpath="out.mjil", 
        encoding="", replace_map = None):
    if replace_map is None:
        if encoding.lower() in ['gbk', 'gb2312', 'cp936']: 
            replace_map = {'・': '.', 'ﾟ': '.', '･':'.', 'ﾞ':'"', '♪':'.', '､': '、', 'ﾄ':' ', '∀':' '}
    prefix = "" if encoding=="" else f"[[{encoding}]]"

    with codecs.open(orgpath, 'r', 'utf8') as fp:
        lines = fp.readlines()
    mjils = [load_mjil(line) for line in lines]
    mjils_map = dict()
    for i, mjil in enumerate(mjils):
        if mjil is None: continue
        mjils_map.update({mjil.addr: i})
    
    ftexts1, ftexts2 = load_ftext(inpath)
    assert(len(ftexts1)==len(ftexts2))
    for ftext1, ftext2 in zip(ftexts1, ftexts2):
        assert(ftext1['addr'] == ftext2['addr'])
        addr = ftext2['addr']
        text = prefix + ftext2['text']
        for k, v in replace_map.items():
            text = text.replace(k, v)
        if addr not in mjils_map: continue
        idx = mjils_map[addr]
        textorg = ftext1['text']
        lines[idx] = lines[idx].replace(textorg, text)

    with codecs.open(outpath, 'w', 'utf8') as fp:
        fp.writelines(lines)

    return lines

def debug():
    pass

def main():
    if len(sys.argv) < 3:
        print("majiro_mjiltext e inpath [outpath]")
        print("majiro_mjiltext i[sjis|gbk] inpath orgpath [outpath]")
        return
    if sys.argv[1].lower() == 'e':
        outpath = sys.argv[3] if len(sys.argv) > 3 else "out.txt"
        export_mjiltext(sys.argv[2], outpath)
    elif sys.argv[1].lower()[0] == 'i':
        encoding = sys.argv[1].lower()[1:]
        outpath = sys.argv[4] if len(sys.argv) > 4 else "out.mjis"
        import_mjiltext(sys.argv[2], sys.argv[3], outpath, encoding=encoding)
    else: raise ValueError(f"unknow format {sys.argv[1]}")

if __name__ == '__main__':
    # debug()
    main()
    pass