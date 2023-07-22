import codecs
import os
import sys
from io import BytesIO

def sjis2utf16bom(inpath, outpath="./out.txt"):
    data_utf16bom = BytesIO()
    with open(inpath, 'rb') as fp:
        data_sjis = fp.read()
        try:
            text = data_sjis.decode('sjis')
            print(inpath, "is converting...")
            data_utf16bom.write(codecs.BOM_UTF16_LE)
            data_utf16bom.write(text.encode('utf-16le'))
            if outpath!="":
                data_utf16bom.seek(0, os.SEEK_SET)
                with open(outpath, 'wb') as fp:
                    fp.write(data_utf16bom.read())
                    return data_utf16bom.getbuffer()
        except UnicodeDecodeError:
            print(inpath, "is not JIS file!")

def debug():
    pass

def main():
    if len(sys.argv) < 2:
        print("krkr_sjis2utf16 inpath|indir [outpath|outdir]")
        return

    inpath = sys.argv[1]
    outpath = sys.argv[2] if len(sys.argv) > 2 else "utf16lebom"
    if os.path.isfile(inpath):
        data = sjis2utf16bom(inpath, outpath)
        if data!=None:
            print("%s -> %s converted"%(inpath, outpath))

    elif os.path.isdir(inpath):
        if not os.path.exists(outpath):
            os.makedirs(outpath)
        for root, dirs, files in os.walk(inpath):
            for file in files:
                src = os.path.join(root, file)
                _relpath = os.path.relpath(src, inpath)
                dst =  os.path.join(outpath, _relpath)
                dstdir = os.path.dirname(dst)

                if not os.path.exists(dstdir): os.makedirs(dstdir)
                data = sjis2utf16bom(src, dst)
                if data!=None:
                    print("%s -> %s converted"%(src, dst))
    else: 
        print("invalid inpath|indir:", inpath)
    pass

if __name__ == "__main__":
    #debug()
    main()
    pass