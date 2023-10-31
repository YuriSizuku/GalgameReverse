"""
    for BaranoKiniBaranoSaku psp, 
    decode and encode zp format, 
    v0.1, developed by devseed 
"""
import gzip
import os
import sys
from io import BytesIO

def uncompress_zp(inpath, outdir):
    with open(inpath, 'rb') as fp:
        fp.seek(0xa)
        s = bytearray()
        while True:
            c = fp.read(1)
            if c==b'\x00': break
            s += c
        name = s.decode('utf-8')
    with gzip.open(inpath, 'rb') as fp:
        data = fp.read()
    outpath = os.path.join(outdir, name)
    print(name, "uncompressed")
    with open(outpath, 'wb') as fp:
        fp.write(data)

def compress_zp(inpath, outdir="", *, compresslevel=1, extra_flag=4):
    # making gzip with filename
    name = inpath.split('\\')[-1]
    with open(inpath, 'rb') as fp:
        data = fp.read()
    data_zp = BytesIO()
    fp_zp = gzip.GzipFile(name.encode('utf-8'), mode = 'wb', fileobj=data_zp, compresslevel=compresslevel)
    fp_zp.write(data)
    fp_zp.close()
    
    # header fix
    data_zp.getbuffer()[0x8] = extra_flag # XFL = 4 - compressor used fastest algorithm
    data_zp.getbuffer()[0x9] = 0x3 # unix
    if outdir!="":
        outpath = os.path.join(outdir, name+'.zp')
        with open(outpath, 'wb') as fp:
            fp.write(data_zp.getbuffer())
    print(name, hex(len(data_zp.getbuffer())), "bytes compressed!")
    return data_zp.getbuffer()

def debug():
    uncompress_zp(r"D:\Make\Reverse\BaranoKini_psp\test\付録.gim_org.zp", r"D:\MAKE\Reverse\BaranoKini_psp\intermediate")

def main():
    if len(sys.argv) < 2:
        print("zp d inpath(indir) [outdir]")
        print("zp e inpath(indir) [outdir]")
    
    if sys.argv[1].lower() == 'd':
        func = uncompress_zp
    elif sys.argv[1].lower() == 'e':
        func = compress_zp
    else: print("invalid argument")
    inpath = sys.argv[2]
    if len(sys.argv) >= 4: 
        outdir = sys.argv[3]
    else:
        if os.path.isdir(inpath): outdir = inpath
        else: outdir = os.path.dirname(inpath)
        
    if not os.path.exists(outdir): os.makedirs(outdir)
    if os.path.isfile(inpath):
        func(inpath, outdir)
    else:
        indir = inpath
        for file in os.listdir(inpath):
            inpath = os.path.join(indir, file)
            try:
                func(inpath, outdir)
            except: 
                print(inpath + " error")

if __name__ == "__main__":
    #debug()
    main()
    pass