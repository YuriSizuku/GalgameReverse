"""
    for BaranoKiniBaranoSaku psp, 
    export and import pk archive
    v0.1, developed by devseed 
    
    The import only be valid with vmc.pk
    (which has multi zp in pk archive)

    pk_block[]
    |block_size 4 //block_size = content_size + strlen(name_lst) + 0xc
    |content_size1 4  content_size2 4 
    |block_name 00 //4 bytes align, sjis list
    |content[]  4 //in xxx.vmc,  opcode_addr = pk_index * 4
"""

import gzip
import os
import sys
import re
import struct
from io import BytesIO
import baranoki_psp_zp as zp

def print_pk(path):
    with open(path, "rb") as fp:
        data = fp.read()
    lst_addrs = []
    for t in re.finditer(b'\x2e\x6c\x73\x74', data): # .lst
        i = t.start()
        while data[i] != 0 and i<len(data): i -= 1
        lst_addrs.append(i+1)
    zp_addr = 0
    for addr in lst_addrs:
        if zp_addr!=0:
            print(r"//", hex(addr-zp_addr))
        block_size, unk1, unk2 = struct.unpack("<III", data[addr-12:addr])
        i = addr
        while data[i]!=0 and i<len(data): i+=1
        name_lst = data[addr:i].decode('utf-8')
        name_lst_len = i-addr
        padding_len = 3- i%0x4
        index_addr = i + padding_len + 1
        zp_addr = addr + block_size
        print("[", hex(block_size), hex(unk1), hex(unk2), name_lst, "]")
        for i in range(index_addr, index_addr+block_size-name_lst_len-padding_len-1, 4):
            d = int.from_bytes(data[i:i+4], 'little')
            print(hex(i), d, hex(d), "("+hex(d*4)+")")

def parse_pk(data):
    pk_blocks = []
    i = 0
    while i<len(data):
        block_start = i
        if i+12 > len(data): break 
        block_size, content_size, content_size2 = \
            struct.unpack("<III", data[i:i+12])
        
        # parse block name
        i += 12
        j = i
        while j<len(data) and data[j]!=0: j+=1
        block_name = data[i:j]
        while j<len(data) and data[j]==0: j+=1
        content_start = j
        content_end = (content_start + content_size) if block_size!=0 else len(data)

        pk_blocks.append({
            'block_size':block_size,
            'content_size':content_size,'content_size2':content_size2,
            'block_name':block_name,
            'content':data[content_start:content_end]})
        i = block_start + block_size
        if block_size == 0: break

    return pk_blocks

def write_pk(pk_blocks, outpath, fix_blocksize=True):
    fp = open(outpath, 'wb')
    for pk_block in pk_blocks:
        # index area
        block_addr = fp.tell()
        if fix_blocksize:
            pk_block['content_size'] = len(pk_block['content'])
            pk_block['content_size2'] = pk_block['content_size']
            if pk_block['block_size']>0:
                taddr = block_addr + 0xc + \
                        len(pk_block['block_name'])
                taddr += 4 - taddr%4
                taddr += pk_block['content_size']
                if taddr%4!=0: taddr += 4 - taddr%4
                pk_block['block_size'] = taddr - block_addr

        fp.write(struct.pack("<III", pk_block['block_size'], 
            pk_block['content_size'], pk_block['content_size2']))
        fp.write(pk_block['block_name'])
        fp.write((4-fp.tell()%4) * b'\x00') 

        # content area
        fp.write(pk_block['content'])
        if fp.tell()%4 !=0: fp.write((4-fp.tell()%4) * b'\x00')

    print("%d pk_blocks has been write to %s!" %
            (len(pk_blocks), outpath))
    fp.close()

def export_pk(pkpath, outdir):
    # extract by simple detect the gzip header 1F 8B 08
    with open(pkpath, 'rb') as fp:
        data = fp.read()
    offsets_gz = []
    for m in re.finditer(b'\x1f\x8b\x08', data):
        offsets_gz.append(m.start())
    offsets_gz.append(len(data))
    for i in range(len(offsets_gz)-1):
        j = offsets_gz[i] + 10
        while  j<len(data) and data[j] !=  0: j += 1
        start = offsets_gz[i]
        end = offsets_gz[i+1]
        name = data[start+10: j].decode('utf-8')

        print(hex(start), hex(end) , name)
        path = os.path.join(outdir, name+'.gz')
        with open(path, 'wb') as fp2:
            fp2.write(data[start:end])
        # zp.uncompress_zp(path, outdir)

def export_pk2(pkpath, outdir):
    # extract by parse pk structure
    with open(pkpath, 'rb') as fp:
        data = fp.read()

    pk_blocks = parse_pk(data)
    
    # extract each pk_block
    for i, pk_block in enumerate(pk_blocks):
        content = pk_block['content']
        if content[0:3] == b'\x1f\x8b\x08': # gzip
            try:
                filename = content[0xa: content.find(b'\x00', 0x10)]
                filename = filename.decode('utf-8')
            except UnicodeDecodeError as e:
                print(e, "use index %d in file instead"%(i))
                filename = str(i)

            with open(os.path.join(outdir, filename), 'wb') as fp:
                fp_gz = gzip.GzipFile(fileobj=BytesIO(content), mode='rb')
                fp.write(fp_gz.read())
                fp_gz.close()
        else:
            try:
                filename = pk_block['block_name'].decode('sjis')
            except UnicodeDecodeError as e:
                filename = str(i)
            with open(os.path.join(outdir, filename), 'wb') as fp:
                fp.write(content)
        print(pkpath,  i, filename, "has been extracted")

def import_pk(pkpath, indir, outpath):
    with open(pkpath, "rb") as fp:
        data = bytearray(fp.read())

    pk_blocks = parse_pk(data)

    #  find file to insert block
    for i, pk_block in enumerate(pk_blocks):
        # make searching name list
        filenames = []
        content = pk_block['content']
        flag_zp = False
        if content[0:3] == b'\x1f\x8b\x08': # gzip
            flag_zp = True
            try:
                filename = content[0xa: content.find(b'\x00',0x10)]
                filename = filename.decode('utf-8')
            except UnicodeDecodeError as e:
                print(e, "use index %d in file instead"%(i))
                filename = str(i)
            filenames.append(filename)
        try:
            filename = pk_block['block_name'].decode('sjis')
        except UnicodeDecodeError as e:
            filename = str(i)
        filenames.append(filename)
        
        # search file
        inpath = ""
        for filename in filenames:
            if os.path.exists(os.path.join(indir, filename)):
                inpath = os.path.join(indir, filename)
                break
        if inpath=="": continue

        # rebuild pk block
        print("to insert %s into %s flagzp=%d" %
            (os.path.basename(inpath), 
            os.path.basename(outpath), flag_zp))
        if flag_zp and os.path.splitext(inpath)[1].lower()!='zp':
            pk_block['content'] = zp.compress_zp(inpath,
                outdir="", compresslevel=8, extra_flag=0)
        else:
            with open(inpath, 'rb') as fp:
                pk_block['content'] = fp.read()
    write_pk(pk_blocks, outpath, fix_blocksize=True)

def debug():
    basedir = r"./build/intermediate"
    export_pk2(r"D:\Make\Reverse\BaranoKini_psp\test\title.pk", r"D:\Make\Reverse\BaranoKini_psp\test\title.pk")
    return
    import_pk(os.path.join(basedir, "./afs01/vmc.pk"), 
        os.path.join(basedir, "./vmc"), 
        os.path.join(basedir, "./vmc_test.pk"))
    export_pk2(os.path.join(basedir, "./vmc_test.pk"), 
        os.path.join(basedir, "./vmc_test"))
    pass

def main():
    if len(sys.argv) <= 2:
        print(r"pk e|e2 pkpath [outdir] //export vmc.pk ")
        print(r"pk i pkpath indir [outpath] // import *.vmc in indir to vmc.pk")
        return
    if sys.argv[1].lower() == 'e':   
        pkpath = sys.argv[2]
        if len(sys.argv) <= 3: outdir = os.path.dirname(pkpath)
        else: outdir = sys.argv[3]
        export_pk(pkpath, outdir)
    elif sys.argv[1].lower() == 'e2':
        pkpath = sys.argv[2]
        if len(sys.argv) <= 3: outdir = os.path.dirname(pkpath)
        else: outdir = sys.argv[3]
        export_pk2(pkpath, outdir)
    elif sys.argv[1].lower() == 'i':
        pkpath = sys.argv[2]
        indir = sys.argv[3]
        if len(sys.argv) == 4: outpath = pkpath+'.pk'
        else: outpath = sys.argv[4]
        import_pk(pkpath, indir, outpath)
    else:
        print("invalid option: ",  sys.argv[1])
    pass

if __name__ == '__main__':
    #debug()
    main()
    pass