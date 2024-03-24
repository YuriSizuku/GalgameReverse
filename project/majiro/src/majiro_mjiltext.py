"""
majiro engine, mjil text export import   
  v0.1.4, developed by devseed
　the multi encoding annotation [[cp936]] is for mjotool2 modified by me

tested game: 
  そらいろ (ねこねこソフト) v1.1
  ルリのかさね ～いもうと物語り (ねこねこソフト)

See also,  
https://github.com/AtomCrafty/MajiroTools
https://github.com/trigger-segfault/majiro-py

"""

import os
import sys
import re
import codecs
from collections import namedtuple 
from typing import Union, List, Dict

sys.path.append(os.path.join(os.path.dirname(__file__), r"compat"))
try:
    from compat.libutil_v600 import save_ftext, load_ftext, ftext_t
except ImportError as e:
    exec("from compat.libutil_v600 import save_ftext, load_ftext, ftext_t")

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
    # debug()
    main()
    pass

"""
history:
v0.1, initial version
v0.1.2, add mjil_call_selectmenu_pattern
v0.1.3, add mjil_callp_ruby_pattern
v0.1.4, change ftext to libutil v0.6
"""