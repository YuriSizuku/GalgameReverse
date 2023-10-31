import os
import sys
import codecs

def merge_chsjp_text(jpdir, chsdir, outdir):
    errlines = []
    errfilepath = os.path.join(outdir, "err.txt") 
    for file in os.listdir(jpdir):
        if os.path.splitext(file)[1] != '.txt': continue
        print(file)
        jplines = []
        chslines = []
        with open(os.path.join(jpdir, file), 'rb') as fp:
            data = fp.read()
            i = 0
            while i < len(data):
                end = data.find(b'\n', i)
                if end==-1: end = len(data)
                line_data = data[i:end+1]
                try: 
                    line = line_data.decode('sjis')
                except:
                    print(hex(i))
                    line_data = line_data.replace(b'\x87\x81', b'\x81\x68')
                    line_data = line_data.replace(b'\x87\x80', b'\x81\x67')
                    line_data = line_data.replace(b'\x9c\xff', b'\x81\x40')
                    # line_data = re.sub(b'\x87.', '・'.encode('sjis'), line_data)
                    line = line_data.decode('sjis')
                jplines.append(line)
                i = end + 1
        with codecs.open(os.path.join(chsdir, file), 'r', 'gbk') as fp:
            i = 0
            errlines.append(file + " chs\n")
            try:
                line = fp.readline()
            except UnicodeDecodeError:
                line = "#UNICODE_ERR"
                errlines.append("#"+str(i)+"\n")
            while line:
                chslines.append(line)
                try:
                    line = fp.readline()
                except UnicodeDecodeError:
                    line = "#UNICODE_ERR"
                    errlines.append("#"+str(i)+"\n")
                i += 1
        with codecs.open(os.path.join(outdir, file), 'w', 'utf-8') as fp:
            for i, (jpline, chsline) in enumerate(zip(jplines, chslines)):
                jpline = jpline.strip('\n').strip('\r')
                chsline = chsline.strip('\n').strip('\r')
                
                chsline = chsline.replace("仈", "＃")
                chsline = chsline.replace("亹", "＄")
                
                chsline = chsline.replace("偅", "。")
                chsline = chsline.replace("偂", "，")
                chsline = chsline.replace("偉", "、")
                chsline = chsline.replace("僅", "”")
                chsline = chsline.replace("偭", "》")
                chsline = chsline.replace("僁", "？")
                chsline = chsline.replace("傿", "！")
                chsline = chsline.replace("偋", "」")
                chsline = chsline.replace("偐", "』")
                chsline = chsline.replace("傽", "）")

                fstr1 = "○{idx:04}○ {text}\n"
                fstr2 = fstr1.replace('○', '●')+"\n"
                fp.write(fstr1.format(idx=i, text=jpline))
                fp.write(fstr2.format(idx=i, text=chsline))
        # with open(errfilepath, "w") as fp:
        #     fp.writelines(errlines)
        print(file+", "+ str(len(jplines))+" merged!")

def debug():
    pass

def main():
    if len(sys.argv) < 2:
        print("merge_chsjp_text jpdir chsdir outdir")
    merge_chsjp_text(sys.argv[1], sys.argv[2], sys.argv[3])

if __name__ == "__main__":
    # debug()
    main()
    pass
