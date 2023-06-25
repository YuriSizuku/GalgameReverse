 # -*- coding: utf-8 -*-
"""
Some functions about the text manipulate, such as match text, text length, etc.
    v0.2.2, developed by devseed
"""

from pickle import TRUE
import re
import codecs
from io import StringIO
from typing import Callable, Tuple, Union, List, Dict

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
        addr_width = len(hex(d))-2
    if size_width==0:
        d = max([t['size'] for t in ftexts1])
        size_width = len(hex(d))-2

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

# libtext functions
def lcs(s1:str, s2:str) -> List[List[int]]:
    """
    calculate the longeset common sequence legth of s1 and s2
    """
    l1, l2 = len(s1), len(s2)
    if l1 == 0: return l2
    if l2 == 0: return l1
    res = [[0 for j in range(l2+1)] for i in range(l1+1)]
    for i in range(1, l1+1):
        for j in range(1, l2+1):
            if s1[i-1] == s2[j-1]: res[i][j] = res[i-1][j-1] + 1
            else: res[i][j] = max(res[i-1][j], res[i][j-1])
    return res[-1][-1]

def distance_lcs(s1: str, s2: str) -> int:
    return len(s1) + len(s2) - 2 * lcs(s1, s2)

def distance_Levenshtein(s1: str, s2: str) -> int:
    
    l1, l2 = len(s1), len(s2)
    if l1 == 0: return l2
    if l2 == 0: return l1
    res = [[0 for j in range(l2)] for i in range(l1)]
    for i in range(0, l1):
        for j in range(0, l2):
            if min(i, j) == 0: # empty string, insert all in s1
                res[i][j] = max(i, j)
            else: 
                t = 1 if s1[i] != s2[j] else 0
                res[i][j] = min(
                    res[i-1][j] + 1, # insert 1 char in s1
                    res[i][j-1] + 1, # delete 1 char in s1
                    res[i-1][j-1] + t # replace 1 char in s1 if s1[1] != s2[j]
                )
    return res[-1][-1]

def match_texts(texts1: List[str], 
    texts2: List[str], max_ratio=0.1, max_dist=-1, *, 
    f_dist: Callable[[str, str], int]=None, 
    f_threshod: Callable[[str, str, int], bool]=None)\
    -> Tuple[List[int], List[int]]:
    """
    match the texts1 with texts2 by edit_distance_lcs
    :param max_ratio: the threshod ratio in matching, dist/len(text1), 
    :param max_dist: the threshod distance in matching,  -1 main all length accept
    :param f_dist: f_dist(s1, s2), calculate the distance of two text
    :param f_theshod:  f_theshod(t1, t2, dist), if skip match, return False
    :return: texts1_match, texts2_match. The position list, if not matched, index -1
    """ 

    def _defalut_threshod(t1, t2, dist):
        if dist/len(t1) > max_ratio: return False
        if max_dist != -1 and dist > max_dist: return False

    if f_dist == None: f_dist = distance_Levenshtein
    if f_threshod == None: f_threshod = _defalut_threshod
    texts1_match = [-1] * len(texts1)
    texts2_match = [-1] * len(texts2)
    for i, t1 in enumerate(texts1):
        min_idx = -1
        min_dist = -1
        for j, t2 in enumerate(texts2):
            if texts2_match[j] != -1: continue
            dist = f_dist(t1, t2)
            if dist == 0:
                min_idx = j
                break
            if f_threshod(t1, t2, dist) is False: continue

            if min_idx == -1:
                min_idx = j
                min_dist = dist
            else:
                if dist < min_dist:
                    min_idx = j
                    min_dist = dist
                elif dist == min_dist:
                    if abs(j-i) < abs(min_idx-i):
                        min_idx = j
                        min_dist = dist
        if min_idx != -1:
            texts1_match[i] = min_idx
            texts2_match[min_idx] = i

    return texts1_match, texts2_match 

def count_textglphy(text: str) -> Dict[str, int]:
    """
    :param text, the text to count glphy
    :param sort_order, 0, no sort, 1 order, -1 reverse order
    """
    glphy_map = dict()
    for c in text:
        if c in glphy_map: glphy_map[c] += 1
        else: glphy_map[c] = 1
    return glphy_map

def count_ftextglphy(
    ftexts: List[Dict[str, Union[int, str]]]) \
    -> Tuple[bytes, Dict[str, int]]:
    """
    :return all_text, glphy_map from ftexts
    """

    all_text = StringIO()
    for ftext in ftexts:
        all_text.write(ftext['text'])
    glphy_map = count_textglphy(all_text.getvalue())
    return all_text.getvalue(), glphy_map

def count_ftextfilesglphy(filepaths: List[str])\
    -> Tuple[bytes, Dict[str, int]]:

    ftexts = []
    for path in filepaths:
        _, ftexts2 = load_ftext(path, TRUE)
        ftexts.extend(ftexts2)
    return count_ftextglphy(ftexts)

def write_ftext(
    ftexts1: List[Dict[str, Union[int, str]]], 
    ftexts2: List[Dict[str, Union[int, str]]], 
    filename: str, outpath="",  *, num_width=5,
    addr_width=6, size_width=3) -> List[str]:
    """ 
    # filename="xxx", n=d
    "●(.*)●[ ](.*)
    """

    lines = []
    # write header to line
    if filename != "":
        n1 = 0 if ftexts1==None else len(ftexts1)
        n2 = 0 if ftexts1==None else len(ftexts1)
        fstrfile = "# filename=\"{filename}\" n1={n1:d} n2={n2:d}\n"
        lines.append(fstrfile.format
            (filename=filename, n1=n1, n2=n2))
    
    # write content to line
    lines.extend(dump_ftext(ftexts1, ftexts2, 
        num_width=num_width, addr_width=addr_width, 
        size_width=size_width))
    if outpath!="":
        with codecs.open(outpath, 'w', 'utf-8') as fp:
            fp.writelines(lines)
    return lines

def write_ftextpack(
    filepacks: List[Dict[str, Union[str, List]]], 
    outpath:str = "",  *, num_width=5, 
    addr_width=6, size_width=3) -> List[str]:
    """
    write multi ftexts into one file, 
        with the filename information
    :param filepaths: 
        [{'filename':, 'ftexts1': , 'ftexts2': }]
    """
    
    lines = []
    for t in filepacks:
        lines = write_ftext(
            t['ftexts1'], t['ftexts2'], t['filename'], 
            num_width=num_width, addr_width=addr_width, 
            size_width=size_width)
        lines.extend(lines)
    if outpath != "":
        with codecs.open(outpath, 'w', 'utf-8') as fp:
            fp.writelines(lines)
    return lines

def read_ftextpack(
    inobj: Union[str, List[str]], only_text=False)\
    -> List[Dict[str, Union[str, List]]]:
    """
    :param inobj: inobj can be path or lines_text
    """

    filepacks = []
    filename = "NULL"
    start = -1
    
    if type(inobj) == str:
         with codecs.open(inobj, 'r', 'utf-8') as fp:
             lines = fp.readlines()
    else: lines = inobj

    for i, line in enumerate(lines):
        m = re.search(r'^#(.+?)filename="(.+?)"', line)
        if m != None:
            if start == -1: 
                start = i
                filename = m.group(2)
                continue
            ftexts1, ftexts2 = load_ftext(
                lines[start:i], only_text=False)
            filepacks.append( {'filename':filename, 
                'ftexts1':ftexts1, 'ftexts2':ftexts2})
            filename = m.group(2)
            start = i
    ftexts1, ftexts2 = load_ftext(
        lines[start:len(lines)], only_text=False)
    filepacks.append({'filename' : filename, 
        'ftexts1' : ftexts1, 'ftexts2' : ftexts2})

    return filepacks

"""
history:
v0.1, match_texts, write_format_multi, read_format_multi
v0.2, count_glphy for building font
v0.2.1, fix read_format_multi bug
v0.2.2, add typing hint and no dependency to bintext
"""