"""
majiro engine, mjil text export import   
  v0.1.5, developed by devseed
　the multi encoding annotation [[cp936]] is for mjotool2 modified by me

tested game: 
  そらいろ (ねこねこソフト) v1.1
  ルリのかさね ～いもうと物語り (ねこねこソフト)

refer:  
https://github.com/AtomCrafty/MajiroTools
https://github.com/trigger-segfault/majiro-py
"""

__VERSION__ = "v0.1.5"

# region util functions
from typing import List, Tuple, Union
from dataclasses import dataclass
@dataclass
class ftext_t:
    addr: int = 0
    size: int = 0
    text: str = ""

def save_ftext(ftexts1: List[ftext_t], ftexts2: List[ftext_t], 
        outpath: str = None, *, encoding="utf-8", width_index = (5, 6, 3)) -> List[str]:
    """
    format text, such as ●num|addr|size● text
    :param ftexts1[]: text dict array in '○' line, 
    :param ftexts2[]: text dict array in '●' line
    :return: ftext lines
    """

    width_num, width_addr, width_size = width_index
    if width_num==0: width_num = len(str(len(ftexts1)))
    if width_addr==0: width_addr = len(hex(max(t.addr for t in ftexts1))) - 2
    if width_size==0: width_size = len(hex(max(t.size for t in ftexts1))) - 2

    lines = []
    fstr1 = "○{num:0%dd}|{addr:0%dX}|{size:0%dX}○ {text}\n" \
            % (width_num, width_addr, width_size)
    fstr2 = fstr1.replace('○', '●')
    if not ftexts1: ftexts1 = [None] * len(ftexts2)
    if not ftexts2: ftexts2 = [None] * len(ftexts1)
    for i, (t1, t2) in enumerate(zip(ftexts1, ftexts2)):
        if t1: lines.append(fstr1.format(num=i, addr=t1.addr, size=t1.size, text=t1.text))
        if t2: lines.append(fstr2.format(num=i, addr=t2.addr, size=t2.size, text=t2.text))
        lines.append("\n")

    if outpath: 
        with open(outpath, "wt", encoding=encoding) as fp:
            fp.writelines(lines)

    return lines 

def load_ftext(inpath: Union[str], *, 
        encoding="utf-8") -> Tuple[List[ftext_t], List[ftext_t]]:
    """
    format text, such as ●num|addr|size● text
    :param inobj: can be path, or lines[], in the end, no \r \n
    :return: ftexts1[]: text dict array in '○' line, 
             ftexts2[]: text dict array in '●' line
    """

    ftexts1, ftexts2 = [], []

    with open(inpath, "rt", encoding=encoding) as fp:
        lines = fp.readlines()

    if len(lines) > 0: lines[0] = lines[0].lstrip("\ufeff") # remove bom
    for line in lines:
        line = line.rstrip("\n").rstrip("\r")
        if len(line) <= 0: continue
        indicator = line[0]
        if indicator == "#": continue
        if indicator not in {"○", "●"}: continue
        _, t1, *t2 = line.split(indicator)
        t2 = "".join(t2)
        ftext = ftext_t(-1, 0, t2[1:])
        try: 
            _, t12, t13 = t1.split('|')
            ftext.addr, ftext.size = int(t12, 16), int(t13, 16)
        except ValueError: pass 
        if indicator=='○': ftexts1.append(ftext)
        else: ftexts2.append(ftext)

    return ftexts1, ftexts2
# endregion

import os
import sys
import re
import codecs
from collections import namedtuple 
from typing import List

# mjil functions
mjil_pattern = re.compile(r'(\S+): (\S+)\s*(.+?)[\r\n]+')
mjil_call_option_pattern = re.compile(r'\$57f252db \((\d+)\)')
mjil_call_selectmenu_pattern = re.compile(r'\$\$select@MENU \((\d+)\)')
mjil_callp_ruby_pattern = re.compile(r'\$3198fd01 \((\d+)\)')
mjil_callp_ruby2_pattern = re.compile(r'\$2f93f26a \((\d+)\)')
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
    
    ftexts:  List[ftext_t] = []
    for i, mjil in enumerate(mjils):
        if mjil.opcode == "text": # normal text
            ftexts.append(ftext_t(mjil.addr, 0, mjil.operand.strip('"')))
            
        elif mjil.opcode == "call": # call text
            m = re.search(mjil_call_option_pattern, mjil.operand)
            if m: # option
                n = int(m.group(1))
                for j in range(n-2):
                    if mjils[i-n+j].opcode != "ldstr": continue
                    ftexts.append(ftext_t(mjils[i-n+j].addr, 0, 
                                          mjils[i-n+j].operand.strip('"')))
                continue
            m = re.search(mjil_call_selectmenu_pattern, mjil.operand)
            if m: # select menu
                n = int(m.group(1))
                for j in range(n):
                    if mjils[i-n+j].opcode != "ldstr": continue
                    ftexts.append(ftext_t(mjils[i-n+j].addr, 0, 
                                          mjils[i-n+j].operand.strip('"')))
                continue

        elif  mjil.opcode == "callp": # callp text
            m = re.search(mjil_callp_ruby_pattern, mjil.operand)
            if m is None: m = re.search(mjil_callp_ruby2_pattern, mjil.operand)
            if m : # ruby text
                n = int(m.group(1))
                for j in range(n):
                    if mjils[i-n+j].opcode != "ldstr": continue
                    ftexts.append(ftext_t(mjils[i-n+j].addr, 0, 
                                          mjils[i-n+j].operand.strip('"')))
                continue
    
    return save_ftext(ftexts, ftexts, outpath)

def import_mjiltext(inpath, orgpath, outpath="out.mjil", 
        encoding="", replace_map = None):
    if replace_map is None:
        if encoding.lower() in ['gbk', 'gb2312', 'cp936']: 
            replace_map = {'・': '.', 'ﾟ': '.', '･':'.', 'ﾞ':'"', '♪':'.', '､': '、', 'ﾄ':' ', '∀':' ', r"\u3000": "　"}
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
    for t1, t2 in zip(ftexts1, ftexts2):
        assert(t1.addr == t2.addr)
        addr = t2.addr
        text = prefix + t2.text
        for k, v in replace_map.items(): text = text.replace(k, v)
        if addr not in mjils_map: continue
        idx = mjils_map[addr]
        textorg = t1.text
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
    main()

"""
history:
v0.1, initial version
v0.1.2, add mjil_call_selectmenu_pattern
v0.1.3, add mjil_callp_ruby_pattern
v0.1.4, change ftext to libutil v0.6
v0.1.5, remove the depend of libutil
"""