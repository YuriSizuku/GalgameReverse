# -*- coding: utf-8 -*-
"""
for nature valaciton chs localization, 
export and import text in hibiki kag format
    v0.1, developed by devseed
"""

import re
import codecs
import argparse

# ●p000|9999|[name]● text, 
# the text can not be multi line, should be using r'\n' in the inner text, no need to put r'\n' in the end

def extract_hibiki_ks(inpath, outpath):
    def _next_validline(i):
        while i < len(lines): 
            line = lines[i].lstrip().strip('\n').strip('\r')
            if line == "": i += 1
            else: break
        return i

    fin = codecs.open(inpath, 'r', 'utf-8')
    fout = codecs.open(outpath, 'w', 'utf-8')
    lines = fin.readlines()
    i = 0
    while i < len(lines):
        text = ""
        name = ""
        p_idx = ""
        line = lines[i].lstrip().strip('\n').strip('\r')
        # print(line)

        if line=="" or line[0]==';': 
            i += 1
            continue

        if line[0] == '*' and line[1] == 'p':  # text
            p_idx = line[1:-1]
            i = _next_validline(i+1)

            while i < len(lines):
                line = lines[i].lstrip().strip('\n').strip('\r')
                if  line == "" or line[0] == "*":
                    break
                if line[0]==";":
                    i += 1
                    continue
                if line.find("@nm") != -1:
                    m = re.search(r"@nm\s*t=\"(.+?)\"", line)
                    name = m.group(1) if m is not None else name
                    if name!="":
                        fout.write("○{p_idx}|{i:04d}|{name}○\n"
                                    .format(p_idx=p_idx, i=i, name=name))
                        fout.write("●{p_idx}|{i:04d}|{name}●\n\n"
                                    .format(p_idx=p_idx, i=i, name=name))
                        i = _next_validline(i+1)
                    else: i+= 1
                elif line[0] != "@" :
                    text = lines[i]
                    if text!="":
                        fout.write("○{p_idx}|{i:04d}|○ {text}"
                                    .format(p_idx=p_idx, i=i, text=text))
                        fout.write("●{p_idx}|{i:04d}|● {text}\n"
                                    .format(p_idx=p_idx, i=i, text=text ))
                    i += 1
        i += 1
    fin.close()
    fout.close()

def import_hibiki_ks(textpath, insertpath, outpath):
    ftext = codecs.open(textpath, 'r', 'utf-8')
    fins = codecs.open(insertpath, 'r', 'utf-8')
    fout = codecs.open(outpath, 'wb', 'utf-8')
    lines_ins = fins.readlines()
    lines_text = ftext.readlines()
    re_line = re.compile(r"●(.*)\|(\d*)\|(.*)●[ ](.*)")
    for line in lines_text:
        line = line.strip("\n")
        m = re_line.match(line)
        if m is not None:
            idx = int(m.group(2))
            name = m.group(3)
            text = m.group(4)
            # print(idx, name, text)
            if name!="":
                lines_ins[idx] = re.sub(r"@nm\s*t=\"(.+?)\"(.*)$", '@nm t="' + name+'"'+ r"\2", lines_ins[idx])
            else:
                lines_ins[idx] = text + '\n'
    for line in lines_ins:
        # print(line)
        fout.write(line)
    ftext.close()
    fins.close()
    fout.close()

def main():
    parser = argparse.ArgumentParser(description = 'extract or insert text in hibiki ks text')
    parser.add_argument('input', type=str)
    parser.add_argument('--insert', '-i', type=str, default="", help='insert the text to script')
    parser.add_argument('--output', '-o', type=str, default="", help='output utf-8 sjis text path')
    args = parser.parse_args()  
    inpath = args.input
    outpath = args.output
  
    if args.insert != "":
        if outpath=="": outpath = inpath+'.ks' 
        import_hibiki_ks(inpath, args.insert, outpath)
    else:
        if outpath=="": outpath = inpath+'.txt'
        extract_hibiki_ks(inpath, outpath)    

def debug():
    extract_hibiki_ks(r"01姉_00_01.ks", r"01姉_00_01.ks.txt")

if __name__=='__main__':
   # debug()
   main()
   pass