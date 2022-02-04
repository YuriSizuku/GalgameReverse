import os
import sys
import codecs

def text_encoding_convert(inpath, encoding_org, encoding_new, outpath="out"):
    fp = codecs.open(inpath, 'r', encoding=encoding_org)
    fp2 = codecs.open(outpath, 'w', encoding=encoding_new)
    lines = fp.readlines()
    fp2.writelines(lines)
    fp.close()
    fp2.close()

def main():
    if len(sys.argv) < 4:
        print("file_encoding_convert inpath encoding_org encoding_new [outpath]")
    outpath = "out" if len(sys.argv) <5 else sys.argv[4]
    text_encoding_convert(sys.argv[1], sys.argv[2], sys.argv[3], outpath)

if __name__ == "__main__":
    main()