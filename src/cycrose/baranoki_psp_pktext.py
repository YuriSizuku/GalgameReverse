"""
    for BaranoKiniBaranoSaku psp
    this is for import the text with sjis @filename, in .pk files
    v0.1, developed by devseed
"""

from io import BytesIO
import sys

sys.path.append(r".\..\..\util\script")
try:
    import zzbintext as bintext
except:
    import bintext

def insert_pktext(pkpath, textpath, tblpath, outpath="out"):
    with open(pkpath, 'rb') as fp:
        data = bytearray(fp.read())
    _, ftexts2 = bintext.read_format_text(textpath)
    tbl = bintext.load_tbl(tblpath)
    for ftext in ftexts2:
        addr,text,size = ftext['addr'],ftext['text'],ftext['size']
        fileflag = False
        buf = BytesIO()
        for c in text:
            if c=='@':
                fileflag = True
                buf.write(b'@')
                continue
            if c == ' ':
                fileflag = False
                buf.write(b' ')
                continue
            
            if fileflag: charcode = c.encode('sjis')
            else: charcode = bintext.encode_tbl(c, tbl)
            buf.write(charcode)
        
        buf = bytearray(buf.getbuffer())
        if len(buf) <= size:
            data[addr:addr+len(buf)] = buf
            data[addr+len(buf): addr+size] = (size-len(buf)) * b' '
        else:
            print("%x, %d > %d"%(addr, len(buf), size))

    with open(outpath, 'wb') as fp:
        fp.write(data)

def debug():
    pass

def main():
    if len(sys.argv) < 5:
        print("pktext i pkpath textpath tblpath [outpath]")
        return
    
    outpath = sys.argv[5] if len(sys.argv)>5 else "./out"
    if sys.argv[1].lower() == 'i':
        insert_pktext(sys.argv[2], sys.argv[3], sys.argv[4], outpath)
    else:
        print("Invalid argument,", sys.argv[1])

if __name__ == "__main__":
    #debug()
    main()
    pass