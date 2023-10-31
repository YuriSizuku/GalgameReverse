"""
    This script is for matching the pc text 
    and psv text in ftexts format
    v0.1, developed by devseed,

    ftexts is as  {'addr':, 'size':, 'text':} dict list, written like: 

    ○00000|000006|000○ 聖堂での恥ずかしい一幕を何とかやり過ごし――
    ●00000|000006|000● 圣堂那令人羞耻的一幕过后——

    see more in: https://github.com/YuriSizuku/GalgameReverse/blob/master/scripts/bintext.py#L96

    lucatext is in lua format

    tbl convert
    awk  '{print $4"="$2}'  ./tbl.txt |  sed   "1,2d"  | sed "1c0020= "> ./flowers_psv.tbl

"""
import re
import os
import sys
import codecs
from io import StringIO

sys.path.append(r".\..\..\util\script")
try:
    import zzbintext as bintext 
    import zzlibtext as text
except:
    import bintext 
    import libtext as text

g_dataflow_info = """
data flow:
SCRIPT.PAK -> SCRIPT -> SCRIPT_lucatext -> SCRIPT_text + (jpchs_text->jpchs_text2) -> SCRIPT_text_merge + addedtext.txt

SCRIPT_text_merge + addedtext.txt -> SCRIPT_lucatext_rebuild -> SCRIPT_rebuild -> SCRIPT_rebuild.PAK
"""

addedtext_name = "addedtext.txt"

def halfkana2widehira(text): 
    widetext = StringIO()
    # https://github.com/shogo4405/KanaXS
    map = {0xFF67:0x30A1,0xFF68:0x30A3,0xFF69:0x30A5,0xFF6A:0x30A7,0xFF6B:0x30A9,0xFF70:0x30FC,0xFF71:0x30A2,0xFF72:0x30A4,0xFF73:0x30A6,0xFF74:0x30A8,0xFF75:0x30AA,0xFF76:0x30AB,0xFF77:0x30AD,0xFF78:0x30AF,0xFF79:0x30B1,0xFF7A:0x30B3,0xFF7B:0x30B5,0xFF7C:0x30B7,0xFF7D:0x30B9,0xFF7E:0x30BB,0xFF7F:0x30BD,0xFF80:0x30BF,0xFF81:0x30C1,0xFF82:0x30C4,0xFF83:0x30C6,0xFF84:0x30C8,0xFF85:0x30CA,0xFF86:0x30CB,0xFF87:0x30CC,0xFF88:0x30CD,0xFF89:0x30CE,0xFF8A:0x30CF,0xFF8B:0x30D2,0xFF8C:0x30D5,0xFF8D:0x30D8,0xFF8E:0x30DB,0xFF8F:0x30DE,0xFF90:0x30DF,0xFF91:0x30E0,0xFF92:0x30E1,0xFF93:0x30E2,0xFF94:0x30E4,0xFF95:0x30E6,0xFF96:0x30E8,0xFF97:0x30E9,0xFF98:0x30EA,0xFF99:0x30EB,0xFF9A:0x30EC,0xFF9B:0x30ED,0xFF9C:0x30EF,0xFF9D:0x30F3,0xFF9E:0x309B,0xFF9F:0x309C,0xFF66:0x30F2,0xFF6F:0x30C3,0xFF6C:0x30e3,0xFF6D:0x30E5,0xFF6E:0x30e7} # halfkata -> widekata
    map.update({ord('｡'):ord('。'), ord('｢'):ord('「'), ord('｣'):ord('」'), ord('､'):ord('、'), ord('･'):ord('・'),})

    for c in text:
        if ord(c) >=  ord('｡') and ord(c) < ord('ｦ'):
            c = chr(map[ord(c)])
        elif ord(c) >= ord('ｦ')  and ord(c) <=  ord('ﾝ'):
            d = map[ord(c)]
            d = d - 0x0060 if 0x30A1 <= d and d <= 0x30F6 else d # widekata -> widehira
            c = chr(d)
        widetext.write(c)
    return widetext.getvalue()

def lucaluat2ftext(indir, outdir):
    for file in os.listdir(indir):
        if os.path.splitext(file)[1] != '.lua': continue
        ftexts = []
        with codecs.open(os.path.join(indir, file), 'r', 'utf-8') as fp:
            for i, line in enumerate(fp.readlines()):
                m = re.search(r'\(\$j\)"(.+?)"', line)
                if m != None:
                    _text = m.group(1)
                    _text = halfkana2widehira(_text)
                    if not any([bintext.isCjk(x) for x in _text]): continue # no cjk
                    if line.find("SELECT")!=-1 : 
                        for j, s in enumerate(_text.split("$d")):
                            ftexts.append({'addr':i, 'size':len(s), 'text':"[SELECT"+str(j)+"]"+s})
                    else:
                        ftexts.append({'addr':i, 'size':len(ftexts), 'text':_text})
        file = os.path.splitext(file)[0] + '.txt'
        bintext.write_format_text(os.path.join(outdir, file), ftexts, ftexts)
        print(file+" done with " + str(len(ftexts)) + " texts")

def ftext2lucalua(lucadir, textdir, outdir, tblpath=""):
    file_ftexts = text.read_ftextpack(os.path.join(textdir, addedtext_name))
    tbl = None
    if tblpath!="": tbl = bintext.load_tbl(tblpath)
    name_map = dict()
    for t in file_ftexts:
        name_map.update({t['filename']:t})
    for file in os.listdir(lucadir):
        if os.path.splitext(file)[1] != '.lua': continue
        file = os.path.splitext(file)[0] + '.txt'
        if not os.path.exists(os.path.join(textdir, file)): continue 
        ftexts1, ftexts2 = bintext.load_ftext(os.path.join(textdir, file))
        org_len = len(ftexts1) # length without added text
        ftexts1.extend(name_map[file.replace(".lua",".txt")]['ftexts1'])
        ftexts2.extend(name_map[file.replace(".lua",".txt")]['ftexts2'])
        file = os.path.splitext(file)[0] + '.lua'
        with codecs.open(os.path.join(lucadir, file), 'r', 'utf-8') as fp:
            lines = fp.readlines()
        s = ""
        for i, t in enumerate(ftexts2):
            # check select str
            m = re.search(r"\[SELECT(\d)\]", ftexts1[i]['text'])
            if m != None:
                s += ftexts2[i]['text'] + "$d"
                if i < len(ftexts2) - 1: continue

            if m==None or i >= len(ftexts2) - 1:  # to check if select in the end
                if s != "":
                    s = s.rstrip("$d")
                    replaced_str = '($c)"{text}"'.format(text=s)
                    addr = ftexts2[i-1]['addr']
                    lines[addr] = re.sub(r'\(\$j\)"(.+?)"', replaced_str, lines[addr])
                    s = "" 

            # format to luca text
            _text: str = ftexts2[i]['text']
            if ftexts1[i]['text'][-2:] == r'\n' \
                and _text[-2:] != r'\n':
                _text += r'\n'
                
            if tbl is not None:
                j = 0
                lstr = list(_text)
                while j < len(lstr):
                    if lstr[j] != '\n':
                        if bintext.encode_tbl(lstr[j], tbl) is None:
                            lstr[j] = '*'
                    j += 1
                _text = "".join(lstr)
                        
            replaced_str = '($c)"{text}"'.format(text=_text).replace(r'\n', r'\\n')
            if i < org_len:
                lines[t['addr']] = re.sub(r'\(\$j\)"(.+?)"', replaced_str, lines[t['addr']])
            else:
                lines[t['addr']] = re.sub(r'\(\$c\)"(.+?)"', replaced_str, lines[t['addr']])

        file = os.path.splitext(file)[0] + '.lua'
        with codecs.open(os.path.join(outdir, file), 'w', 'utf-8') as fp:
            fp.writelines(lines)
        print(file+" inserted to luca with " + str(len(ftexts2)) + " texts")

def adjust_pctext(indir, outdir): # adjust the pc text format to psv format
    for file in os.listdir(indir):
        if os.path.splitext(file)[1] != '.txt': continue
        ftexts1, ftexts2 = bintext.load_ftext(os.path.join(indir, file), only_text=True)
        i = 0
        while  i < len(ftexts1):
            # name 
            if len(ftexts1[i]['text']) == 0: 
                i += 1
                continue
            if i + 1 < len(ftexts1) and ftexts1[i]['text'][0] == '＃':
                ftexts1[i]['addr'] = i
                ftexts1[i]['text'] = ftexts1[i]['text'].replace('＃', '`') + '@'+ ftexts1[i+1]['text']
                del ftexts1[i+1]
                ftexts2[i]['addr'] = i
                ftexts2[i]['text'] = ftexts2[i]['text'].replace('＃', '`') + '@'+ ftexts2[i+1]['text']
                del ftexts2[i+1]
                
            # name comment, <佐倉涼<さくらりょう> -> $[佐倉涼$/さくらりょう$]
            ftexts1[i]['text'] = re.sub(r'<(.+?)<(.+?)>', r'$[\1$/\2$]', ftexts1[i]['text'])
            ftexts2[i]['text'] = re.sub(r'<(.+?)<(.+?)>', r'$[\1$/\2$]', ftexts2[i]['text'])
            # ＄ -> $d
            ftexts2[i]['text'] = ftexts2[i]['text'].replace('＄', '$d')
            # amiti_é -> amitié
            ftexts2[i]['text'] = ftexts2[i]['text'].replace('amiti_é', 'amitié')
            ftexts2[i]['text'] = ftexts2[i]['text'].replace('_', '')
        
            i += 1

        bintext.write_format_text(os.path.join(outdir, file), ftexts1, ftexts2)
        print(file + " adjust done with " + str(len(ftexts1)) + " texts")

def merge_psv_pc(psvdir, pcdir, outdir):
    file_text_map = []
    for file in os.listdir(psvdir):
        if os.path.splitext(file)[1] != '.txt': continue
        if not os.path.exists(os.path.join(pcdir, file)): continue 
        count = 0
        ftexts_psv1, ftext_psvs2 = bintext.load_ftext(os.path.join(psvdir, file))
        ftexts_pc1, ftexts_pc2 = bintext.load_ftext(os.path.join(pcdir, file), only_text=True)
        texts1 = [re.sub(r"\[SELECT\d\]", "", x['text']) for x in ftexts_psv1]
        texts2 = [x['text'] for x in ftexts_pc1]
        texts1_match, _ = text.match_texts(texts1, texts2, max_ratio=1.0, max_dist=5)
        for i, idx in enumerate(texts1_match) :
            if idx == -1: 
                count += 1
                ftext_psvs2[i]['text'] = "#NO_MATCH"
            else: 
                ftext_psvs2[i]['text'] =  ftexts_pc2[idx]['text']
        bintext.write_format_text(os.path.join(outdir, file), ftexts_psv1, ftext_psvs2)
        print(file + " matched done, " + str(count) + " lines no match")
        ftexts_nomatched = [ftexts_psv1[i] for i, idx in enumerate(texts1_match)  if idx==-1]
        file_text_map.append({'filename':file, 'ftexts1':ftexts_nomatched, 'ftexts2':ftexts_nomatched})
    text.write_ftextpack(os.path.join(outdir, addedtext_name), file_text_map)

def lucatext_extract(basedir):
    script_lucatext = "SCRIPT_lucatext" # original luca text folder
    script_text = "SCRIPT_text" # lucatext -> rawtext
    script_text_merge = "SCRIPT_text_merge" # rawtext + jpchs_text2 -> script_text_merge
    jpchs_text = "jpchs_text" # pc jp_chs text
    jpchs_text2 = "jpchs_text2" # adjusted pc jp_chs text for psv

    lucaluat2ftext(os.path.join(basedir, script_lucatext), 
                os.path.join(basedir, script_text))
    adjust_pctext(os.path.join(basedir, jpchs_text), 
                  os.path.join(basedir, jpchs_text2))
    merge_psv_pc(os.path.join(basedir, script_text),
                 os.path.join(basedir, jpchs_text2), 
                 os.path.join(basedir, script_text_merge))

def lucatext_insert(basedir):
    script_lucatext = "SCRIPT_lucatext" # original luca text folder
    script_lucatext_rebuild = "SCRIPT_lucatext_rebuild" # inserted luca text folder
    script_text_merge = "SCRIPT_text_merge" # rawtext + jpchs_text2 -> script_text_merge
    ftext2lucalua(os.path.join(basedir, script_lucatext), 
               os.path.join(basedir, script_text_merge), 
               os.path.join(basedir, script_lucatext_rebuild))

def main():
    if len(sys.argv) < 3: 
        print(g_dataflow_info)
        print("import text_merge    : flowers_psv_text i basedir")
        print("extract to text_merge: flowers_psv_text e basedir")
        return
    if sys.argv[1] == 'i':
        lucatext_insert(sys.argv[2])
    elif sys.argv[1] == 'e':
        lucatext_extract(sys.argv[2])

def debug():
    lucatext_extract("./build/intermediate4")
    # lucatext_insert("./build/intermediate4")
    pass

if __name__ == "__main__":
    # debug()
    main()
    pass