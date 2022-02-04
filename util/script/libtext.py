 # -*- coding: utf-8 -*-
import os
import re
import codecs
import glob
from io import StringIO
if os.path.exists("binary_text.py"):
    import binary_text
else:
    import zzbinary_text as binary_text
    
"""
libtext.py, by devseed
Some functions about the text maniqulate, such as match text, text length, etc.

v0.1 match_texts, write_format_multi, read_format_multi
v0.2 count_glphy for building font
v0.2.1 fix read_format_multi bug
"""

def lcs(s1, s2):
    """
    calculate the longeset common sequence legth of s1 and s2
    """
    l1, l2 = len(s1), len(s2)
    res = [[0 for j in range(l2+1)] for i in range(l1+1)]
    for i in range(1, l1+1):
        for j in range(1, l2+1):
            if s1[i-1] == s2[j-1]: res[i][j] = res[i-1][j-1] + 1
            else: res[i][j] = max(res[i-1][j], res[i][j-1])
    return res[-1][-1]

def distance_lcs(s1, s2):
    return len(s1) + len(s2) - 2 * lcs(s1, s2)

def distance_Levenshtein(s1, s2):
    l1, l2 = len(s1), len(s2)
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

def match_texts(texts1, texts2, max_ratio=0.1, max_dist=-1, *, 
               f_dist=None, f_threshod=None):
    """
    match the texts1 with texts2 by edit_distance_lcs
    :param max_ratio: the threshod ratio in matching, dist/len(text1), 
    :param max_dist: the threshod distance in matching,  -1 main all length accept
    :param f_dist: f_dist(s1, s2), calculate the distance of two text
    :param f_theshod:  f_theshod(t1, t2, dist), if skip match, return False
    :return: texts1_match, texts2_match. The position list, if not matched, index -1
    """ 
    def defalut_threshod(t1, t2, dist):
        if dist/len(t1) > max_ratio: return False
        if max_dist != -1 and dist > max_dist: return False

    if f_dist == None: f_dist = distance_Levenshtein
    if f_threshod == None: f_threshod = defalut_threshod
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

def count_text_glphy(text):
    """
    :param text, the text to count glphy
    :param sort_order, 0, no sort, 1 order, -1 reverse order
    """
    glphy_map = dict()
    for c in text:
        if c in glphy_map: glphy_map[c] += 1
        else: glphy_map[c] = 1
    return glphy_map

def count_ftexts_glphy(ftexts):
    """
    :return all_text, glphy_map from ftexts
    """
    all_text = StringIO()
    for ftext in ftexts:
        all_text.write(ftext['text'])
    glphy_map = count_text_glphy(all_text.getvalue())
    return all_text.getvalue(), glphy_map

def count_ftextsdir_glphy(ftext_files):
    ftexts = []
    for file in ftext_files:
        _, ftexts2 = binary_text.read_format_text(file, True)
        ftexts.extend(ftexts2)
    return count_ftexts_glphy(ftexts)

def write_format_iter(ftexts1, ftexts2, filename, *, num_width=5, addr_width=6, size_width=3):
    """ 
    # filename="xxx", n=d
    "●(.*)●[ ](.*)
    """
    lines_text = []
    
    if filename != "":
        n1 = 0 if ftexts1==None else len(ftexts1)
        n2 = 0 if ftexts1==None else len(ftexts1)
        fstrfile = "# filename=\"{filename}\" n1={n1:d} n2={n2:d}\n"
        lines_text.append(fstrfile.format(filename=filename, n1=n1, n2=n2))
            
    line_texts = binary_text.write_format_text("", ftexts1, ftexts2, 
                 num_width=num_width, addr_width=addr_width, size_width=size_width)
    lines_text.extend(line_texts)    
    return lines_text

def write_format_multi(outpath, file_ftexts, *, num_width=5, addr_width=6, size_width=3):
    """
    write multi ftexts into one file, with the filename information
    :param file_ftexts[]: {'filename':, 'ftexts1', 'ftexts2'}
    """
    lines_text = []
    for t in file_ftexts:
        lines = write_format_iter(t['ftexts1'], t['ftexts2'], t['filename'], num_width=num_width, 
                                   addr_width=addr_width, size_width=size_width)
        lines_text.extend(lines)
    if outpath != "":
        with codecs.open(outpath, 'w', 'utf-8') as fp:
            fp.writelines(lines_text)
    return lines_text

def read_format_multi(inpath, only_text=False):
    """
    :param inpath: inpath can be path or lines_text
    """
    file_ftexts = []
    filename = "NULL"
    start = -1
    
    if type(inpath) == str:
         with codecs.open(inpath, 'r', 'utf-8') as fp:
             lines_text = fp.readlines()
    else: lines_text = inpath

    for i, line in enumerate(lines_text):
        m = re.search(r'^#(.+?)filename="(.+?)"', line)
        if m != None:
            if start==-1: 
                start = i
                filename = m.group(2)
                continue
            ftexts1, ftexts2 = binary_text.read_format_text(lines_text[start:i], only_text=False)
            file_ftexts.append( {'filename' : filename, 'ftexts1' : ftexts1, 'ftexts2' : ftexts2})
            filename = m.group(2)
            start = i

    ftexts1, ftexts2 = binary_text.read_format_text(lines_text[start:len(lines_text)], only_text=False)
    file_ftexts.append( {'filename' : filename, 'ftexts1' : ftexts1, 'ftexts2' : ftexts2})
    
    return file_ftexts