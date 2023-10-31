# -*- coding: utf-8 -*-
import struct
import codecs
import os
import sys
import argparse
import re

# ●0000|9999|name● text, 
# the text can not be multi line, should be using r'\n' in the inner text, no need to put r'\n' in the end

g_rename_map = { 
    # scenario
    "autosave.ks": "autosave_chs.ks",
    "chara.ks": "chara_chs.ks",
    "hensuu.ks": "hensuu_chs.ks",
    "jukubox.ks": "jukubox_chs.ks",
    "macro.ks": "macro_chs.ks",
    "makuma.ks": "makuma_chs.ks",
    "se001.ks": "se001_chs.ks",
    "se002.ks": "se002_chs.ks",
    "se003.ks": "se003_chs.ks",
    "title_screen.ks": "title_screen_chs.ks",
    "se001.ks": "se001_chs.ks",
    "se002.ks": "se002_chs.ks",
    "se003.ks": "se003_chs.ks",
    "se004.ks": "se004_chs.ks",
    "se005.ks": "se005_chs.ks",
    "se006.ks": "se006_chs.ks",
    "se007.ks": "se007_chs.ks",
    "omake01.ks": "omake01_chs.ks",
    "_se001.ks": "_se001_chs.ks",
    "_se002.ks": "_se002_chs.ks",
    "_se003.ks": "_se003_chs.ks",
    "_se004.ks": "_se004_chs.ks",
    "_se005.ks": "_se005_chs.ks",
    "_se006.ks": "_se006_chs.ks",
    "_se007.ks": "_se007_chs.ks",

    # bgimage
    "0011.jpg": "bg_chs/0011.jpg",
    "0012.jpg": "bg_chs/0012.jpg",
    "0013.jpg": "bg_chs/0013.jpg",
    "0105.jpg": "bg_chs/0105.jpg",
    "0322.jpg": "bg_chs/0322.jpg",
    "1095.jpg": "bg_chs/1095.jpg",
    "1096.jpg": "bg_chs/1096.jpg",
    "2500.jpg": "bg_chs/2500.jpg",
    "2501.jpg": "bg_chs/2501.jpg",
    "2503.jpg": "bg_chs/2503.jpg",
    "4235.jpg": "bg_chs/4235.jpg",
    "7100.jpg": "bg_chs/7100.jpg",
    "7510.jpg": "bg_chs/7510.jpg",
    "7511.jpg": "bg_chs/7511.jpg",
    "7512.jpg": "bg_chs/7512.jpg",
   
    # fgimage, default 
    "default/aload_jikkou.png": "default_chs/aload_jikkou.png", 
    "default/auto_kaihou.png": "default_chs/auto_kaihou.png", 
    "default/autosave_jikko.png": "default_chs/autosave_jikko.png", 
    "default/autosave_luc.png": "default_chs/autosave_luc.png", 
    "default/data_nashi.png": "default_chs/data_nashi.png", 
    "default/ko_josyo.png": "default_chs/ko_josyo.png", 
    "default/ko_teika.png": "default_chs/ko_teika.png", 
    "default/nakayoshi.png": "default_chs/nakayoshi.png", 
    "default/touch.png": "default_chs/touch.png", 
    "default/unlock.png": "default_chs/unlock.png", 

    # fgiamge, default nam_xxx,
    "default/nam_cutlass.png": "default_chs/nam_cutlass.png",
    "default/nam_karasu.png": "default_chs/nam_karasu.png",
    "default/nam_kinon.png":"default_chs/nam_kinon.png",
    "default/nam_kinop.png": "default_chs/nam_kinop.png",
    "default/nam_komachi.png": "default_chs/nam_komachi.png",
    "default/nam_konoka.png": "default_chs/nam_konoka.png",
    "default/nam_Lecultre.png": "default_chs/nam_Lecultre.png",
    "default/nam_marika.png": "default_chs/nam_marika.png",
    "default/nam_marika_z.png": "default_chs/nam_marika_z.png",
    "default/nam_sarara.png": "default_chs/nam_sarara.png",
    "default/nam_sekka.png": "default_chs/nam_sekka.png",
    "default/nam_yoduki.png": "default_chs/nam_yoduki.png",
    "default/nam_yugao.png": "default_chs/nam_yugao.png",

    # fgimage, default prelogue
    "default/f001.png": "default_chs/f001.png", 
    "default/f002.png": "default_chs/f002.png", 
    "default/f003.png": "default_chs/f003.png", 
    "default/f004.png": "default_chs/f004.png", 
    "default/f005.png": "default_chs/f005.png", 
    "default/f006.png": "default_chs/f006.png", 
    "default/f007.png": "default_chs/f007.png", 
    "default/f008.png": "default_chs/f008.png", 
    "default/f009.png": "default_chs/f009.png", 
    "default/f010.png": "default_chs/f010.png", 
    "default/f011.png": "default_chs/f011.png", 
    "default/f012.png": "default_chs/f012.png", 
    "default/f013.png": "default_chs/f013.png", 
    "default/f014.png": "default_chs/f014.png", 
    "default/f015.png": "default_chs/f015.png", 
    "default/f016.png": "default_chs/f016.png", 
    "default/f017.png": "default_chs/f017.png", 
    "default/f018.png": "default_chs/f018.png", 
    "default/f019.png": "default_chs/f019.png", 
    "default/f020.png": "default_chs/f020.png", 
    "default/f021.png": "default_chs/f021.png", 
    "default/f022.png": "default_chs/f022.png", 
    "default/f023.png": "default_chs/f023.png", 
    "default/f024.png": "default_chs/f024.png", 
    "default/ff001.png": "default_chs/ff001.png", 
    "default/ff002.png": "default_chs/ff002.png", 
    "default/ff003.png": "default_chs/ff003.png", 
    "default/ff004.png": "default_chs/ff004.png", 
    "default/ff005.png": "default_chs/ff005.png", 
    "default/ff006.png": "default_chs/ff006.png", 
    "default/fg001.png": "default_chs/fg001.png", 
    "default/fg002.png": "default_chs/fg002.png", 
    "default/fg003.png": "default_chs/fg003.png", 
    "default/fg004.png": "default_chs/fg004.png", 
    "default/fg005.png": "default_chs/fg005.png", 
    "default/fg006.png": "default_chs/fg006.png", 

    # fgiamge, default yy01
    "default/yy01/01.png": "default_chs/yy01/01.png", 
    "default/yy01/02.png": "default_chs/yy01/02.png", 
    "default/yy01/03.png": "default_chs/yy01/03.png", 
    "default/yy01/04.png": "default_chs/yy01/04.png", 
    "default/yy01/05.png": "default_chs/yy01/05.png", 
    "default/yy01/06.png": "default_chs/yy01/06.png", 
    "default/yy01/07.png": "default_chs/yy01/07.png", 
    "default/yy01/08.png": "default_chs/yy01/08.png", 
    "default/yy01/09.png": "default_chs/yy01/09.png", 
    "default/yy01/10.png": "default_chs/yy01/10.png", 
    "default/yy01/11.png": "default_chs/yy01/11.png", 
    "default/yy01/12.png": "default_chs/yy01/12.png", 
    "default/yy01/13.png": "default_chs/yy01/13.png", 
    "default/yy01/14.png": "default_chs/yy01/14.png", 
    "default/yy01/15.png": "default_chs/yy01/15.png", 
    "default/yy01/16.png": "default_chs/yy01/16.png", 
    "default/yy01/17.png": "default_chs/yy01/17.png", 
    "default/yy01/18.png": "default_chs/yy01/18.png", 
    "default/yy01/19.png": "default_chs/yy01/19.png", 
    "default/yy01/20.png": "default_chs/yy01/20.png", 
    "default/yy01/21.png": "default_chs/yy01/21.png", 
    "default/yy01/22.png": "default_chs/yy01/22.png", 
    "default/yy01/23.png": "default_chs/yy01/23.png", 
    "default/yy01/24.png": "default_chs/yy01/24.png", 
    "default/yy01/25.png": "default_chs/yy01/25.png", 
    "default/yy01/26.png": "default_chs/yy01/26.png", 
    "default/yy01/27.png": "default_chs/yy01/27.png", 

    # fgimage, default ss01
    "default/ss01/01_01.png": "default_chs/ss01/01_01.png", 
    "default/ss01/01_02.png": "default_chs/ss01/01_02.png", 
    "default/ss01/01_03.png": "default_chs/ss01/01_03.png", 
    "default/ss01/01_04.png": "default_chs/ss01/01_04.png", 
    "default/ss01/01_05.png": "default_chs/ss01/01_05.png", 
    "default/ss01/01_06.png": "default_chs/ss01/01_06.png", 
    "default/ss01/01_07.png": "default_chs/ss01/01_07.png", 
    "default/ss01/01_08.png": "default_chs/ss01/01_08.png", 
    "default/ss01/01_09.png": "default_chs/ss01/01_09.png", 
    "default/ss01/01_10.png": "default_chs/ss01/01_10.png", 
    "default/ss01/01_11.png": "default_chs/ss01/01_11.png", 
    "default/ss01/01_12.png": "default_chs/ss01/01_12.png", 
    "default/ss01/01_13.png": "default_chs/ss01/01_13.png", 
    "default/ss01/01_14.png": "default_chs/ss01/01_14.png", 
    "default/ss01/01_15.png": "default_chs/ss01/01_15.png", 
    "default/ss01/01_16.png": "default_chs/ss01/01_16.png", 
    "default/ss01/01_17.png": "default_chs/ss01/01_17.png", 
    "default/ss01/01_18.png": "default_chs/ss01/01_18.png", 
    "default/ss01/01_19.png": "default_chs/ss01/01_19.png", 
    "default/ss01/01_20.png": "default_chs/ss01/01_20.png", 
    "default/ss01/01_21.png": "default_chs/ss01/01_21.png", 
    "default/ss01/01_22.png": "default_chs/ss01/01_22.png", 
    "default/ss01/01_23.png": "default_chs/ss01/01_23.png", 
    "default/ss01/01_24.png": "default_chs/ss01/01_24.png", 
    "default/ss01/01_25.png": "default_chs/ss01/01_25.png", 
    "default/ss01/01_26.png": "default_chs/ss01/01_26.png", 
    "default/ss01/01_27.png": "default_chs/ss01/01_27.png", 
    
    # image, button 
    "button/sese01.png":"button_chs/sese01.png",
    "button/sese02.png":"button_chs/sese02.png",
    
    "button/aload.png": "button_chs/aload.png", 
    "button/cnc.png": "button_chs/cnc.png", 
    "button/end.png": "button_chs/end.png", 
    "button/fs.png": "button_chs/fs.png", 
    "button/qload.png": "button_chs/qload.png", 
    
    "button/karasu_a.png": "button_chs/karasu_a.png", 
    "button/kinon_a.png": "button_chs/kinon_a.png", 
    "button/kinop_a.png": "button_chs/kinop_a.png", 
    "button/komachi_a.png": "button_chs/komachi_a.png", 
    "button/konoka_a.png": "button_chs/konoka_a.png", 
    "button/lecoultre_a.png": "button_chs/lecoultre_a.png", 
    "button/marika_a.png": "button_chs/marika_a.png", 
    "button/sarara_a.png": "button_chs/sarara_a.png", 

    "button/nam_Lecultre.png": "button_chs/nam_Lecultre.png", 
    "button/nam_cutlass.png": "button_chs/nam_cutlass.png", 
    "button/nam_karasu.png": "button_chs/nam_karasu.png", 
    "button/nam_kinon.png": "button_chs/nam_kinon.png", 
    "button/nam_kinop.png": "button_chs/nam_kinop.png", 
    "button/nam_komachi.png": "button_chs/nam_komachi.png", 
    "button/nam_konoka.png": "button_chs/nam_konoka.png", 
    "button/nam_marika.png": "button_chs/nam_marika.png", 
    "button/nam_marika_z.png": "button_chs/nam_marika_z.png", 
    "button/nam_sarara.png": "button_chs/nam_sarara.png", 
    "button/nam_sekka.png": "button_chs/nam_sekka.png", 
    "button/nam_yoduki.png": "button_chs/nam_yoduki.png", 
    "button/nam_yugao.png": "button_chs/nam_yugao.png", 
    
    # charactor name
    "【このか】": "【来乃花】",
    "【きのん】": "【树音】",
    "【茉莉煉】": "【茉莉炼】",
    "【カラス】": "【鸦】",
    "【さらら】": "【樱来】",
}

def isCjk(c):
    ranges = [
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

def textCjk(text):
    arr = []
    start = -1
    for i, c in enumerate(text):
        if isCjk(c):
            if start == -1: start = i
        elif start != -1: 
            arr.append(text[start:i]) 
            start = -1
    if isCjk(text[-1]):
        arr.append(text[start:] if start != -1 else text[-1])
    return arr    

def extract_qbit_tyrano_text(inpath, outpath):
    fin = codecs.open(inpath, 'r', 'utf-8')
    fout = codecs.open(outpath, 'w', 'utf-8')
    lines = fin.readlines()
    count=0
    i = 0
    while i < len(lines):
        text = ""
        name = ""
        idx_line = i
        line = lines[i].lstrip().strip('\n')
        # print(line)

        if(line==""): 
            i += 1
            continue

        if line[0] == '#':  #name tag
            name = line[1:-1] if line[-1] == '\n' else  line[1:]
            flag = 0
            while i < len(lines):
                i += 1
                line = lines[i].lstrip().strip('\n')
                if line=="": 
                    text += r"\n"
                    continue
                if line.lstrip()[0] !='#' and len(textCjk(line)):
                    if flag == 0:
                        text = line.strip('\n')
                        flag = 1
                    else:
                        text += r"\n" + line  if line[-1] != '\n' else r"\n" + line[0:-1] 
                else:
                    if line.lstrip()[0] == '#':
                        i -=  1
                    break
            count += 1   
        elif len(textCjk(line)):
            text = line
            count += 1

        if text!="": 
            fout.write("○{:04d}|{:06d}|{name}○ {text}\n"
                    .format(count, idx_line, name=name, text=text ))
            fout.write("●{:04d}|{:06d}|{name}● {text}\n\n"
                    .format(count, idx_line, name=name, text=text ))
        i += 1
    fin.close()
    fout.close()

def import_qbit_tyrano_text(textpath, insertpath, outpath, rename=True):
    ftext = codecs.open(textpath, 'r', 'utf-8')
    fins = codecs.open(insertpath, 'r', 'utf-8')
    fout = codecs.open(outpath, 'wb', 'utf-8')
    lines_ins = fins.readlines()
    lines_text = ftext.readlines()
    re_line = re.compile(r"●(\d*)\|(\d*)\|(.*)●\s*(.*)")
    for line in lines_text:
        line = line.strip("\n")
        m = re_line.match(line)
        if m is not None:
            idx = int(m.group(2))
            name = m.group(3)
            text = m.group(4)
            # print(idx, name, text)
            if name!="":
                lines_ins[idx] = '#' + name + '\n'
                for j, t in enumerate(text.split(r"\n")):
                    if t!="":
                     lines_ins[idx+j+1] = t + '\n'
            else:
                lines_ins[idx] = text + '\n'
    for line in lines_ins:
        # print(line)
        if rename:
            for k, v in g_rename_map.items():
                if line.find(k)==-1: continue
                line = line.replace(k, v) 
                #print(line)
        fout.write(line)
    ftext.close()
    fins.close()
    fout.close()

def merge_text(inpath1, inpath2, outpath):
    with codecs.open(inpath1, "r", encoding="utf-8") as fp:
        text1 = fp.readlines()
    with codecs.open(inpath2, "r", encoding="utf-8") as fp:
        text2 = fp.readlines()  
    text3 = []
    for i in range(len(text2)):
        if(i>len(text1)-1): break
        if text2[i][0] == '●':
            text3.append(text2[i])
        elif text2[i][0] == '○':
            text3.append(text1[i])
        else:
            text3.append(text2[i])
    with codecs.open(outpath, "w", encoding="utf-8") as fp:
        fp.writelines(text3)
    return text3

def rename_text(inpath, outpath):
    with codecs.open(inpath, "r", encoding="utf-8") as fp:
        texts = fp.readlines()
    texts_out = []
    for line in texts:
        for k, v in g_rename_map.items():
            if line.find(k)==-1: continue
            line = line.replace(k, v) 
        texts_out.append(line)
    with codecs.open(outpath, "w", encoding="utf-8") as fp:
        fp.writelines(texts_out)
    return texts_out
    
if __name__=='__main__':
    parser = argparse.ArgumentParser(description = 'extract or insert text in qbit tyrano text')
    parser.add_argument('input', type=str)
    parser.add_argument('--insert', '-i', type=str, default="", help='insert the text to script')
    parser.add_argument('--output', '-o', type=str, default="", help='output utf-8 sjis text path')
    parser.add_argument('--merge', '-m', type=str, default="", help="merge the original with this " )
    parser.add_argument('--rename', '-r', action="store_true", help="redirect the path ")
    args = parser.parse_args()  
    inpath = args.input
    outpath = args.output
  
    if args.merge!="":
        print("merge mode")
        merge_text(inpath, args.merge, outpath)
        exit(0)
    
    if args.rename:
        print("rename mode")
        rename_text(inpath, outpath)
        exit(0)

    if args.insert != "":
        if outpath=="": outpath = inpath+'.inserted.txt' 
        import_qbit_tyrano_text(inpath, args.insert, outpath)
    else:
        if outpath=="": outpath = inpath+'.extract.txt'
        extract_qbit_tyrano_text(inpath, outpath)