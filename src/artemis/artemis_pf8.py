"""
    This is a pack and unpack tool for artemis .pf8 archive 
    v0.2, developed by devseed.

    pf8 structure
    |magic 'pf8'
    |index_size 4 //start from index_count (faddr 0x7)
    |index_count 4
    |file_entrys[]
      |name_length 4
      |name //string with '\0'
      |00 00 00 00
      |offset 4
      |size 4
    |filesize_count 4
    |filesize_offsets[] 8 //offset from faddr 0xf, last is 00 00 00 00 00 00 00 00
    |filesize_count_offset 4 //offset from faddr 0x7

"""
import os
import argparse
import struct
import re
import mmap
import hashlib
from io import BytesIO

def makekeypf8(pf8):
    index_data = pf8['data'][0x7:0x7+pf8['index_size']]
    sha1 = hashlib.sha1(index_data)
    return sha1.digest()

def encryptpf8(buf, start_offset, size, key, cover=True):
    dst = None if cover else bytearray(size)
    for i in range(size):
        if cover:
            buf[start_offset+i] = buf[start_offset+i] ^ key[i % len(key)]
        else:
            dst[i] = buf[start_offset+i] ^ key[i % len(key)]
    return dst

def decryptpf8(buf, start_offset, size, key):
    dst = bytearray(size)
    for i in range(size):
        dst[i] = buf[start_offset+i] ^ key[i % len(key)]
    return dst

def parsepf8(data):
    pf8 = {}
    pf8['data'] = data
    pf8['magic'] = data[0:0x3]
    if pf8['magic'] !=b'pf8':
          print('Errir invalid pf8 file!')
          return None
    pf8['index_size'], pf8['index_count'] = struct.unpack('<II', data[0x3:0xB])

    count = pf8['index_count']
    pf8['file_entrys'] = []
    cur = 0xB
    for _ in range(count):
        name_length = struct.unpack('<I',data[cur:cur+4])[0]
        name = bytes(data[cur+4:cur+8+name_length]).decode(encoding='utf-8')
        cur += name_length+8
        offset, size =struct.unpack('<II', data[cur:cur+8])
        pf8['file_entrys'].append({
          'name_length': name_length, 
          'name':name, 
          'offset': offset,
          'size':size})
        cur += 8

    pf8['filecount'] = struct.unpack('<I', data[cur:cur+4])[0]
    cur += 4
    count = pf8['filecount']
    pf8['filesize_offsets'] = []
    for _ in range(count):
        pf8['filesize_offsets'].append( struct.unpack('<Q',data[cur:cur+8])[0])
        cur += 8
    pf8['filesize_count_offset'] = struct.unpack('<I', data[cur:cur+4])[0]
    return pf8

def makepf8archive(basepath, filelist, unencrpted_filter): 
    # calculate index size
    data_io = BytesIO()
    fileentry_size = 0
    filedata_size = 0
    for name, size in filelist:
        filedata_size += size
        fileentry_size += len(name.encode(encoding='utf-8')) + 16
    index_count = len(filelist)
    index_size = 0x4 + fileentry_size + 0x4 + (index_count+1)*0x8 + 0x4

    # writing index
    data_io.write(b'pf8')
    data_io.write(struct.pack('<II', index_size, index_count))
    fileoffset = index_size + 0x7
    filesize_offsets = []
    for name, size in filelist:
        name_byte =  name.encode(encoding='utf-8')
        name_length = len(name_byte)
        data_io.write(struct.pack('<I', name_length))
        data_io.write(name_byte)
        data_io.write(struct.pack("<III",0x0, fileoffset, size))
        filesize_offsets.append(data_io.tell()-0x4-0xf)
        fileoffset += size
    data_io.write(struct.pack('<I', index_count+1))
    filesize_count_offset = data_io.tell()-0x4-0x7
    for offset in filesize_offsets:
        data_io.write(struct.pack('<Q',  offset))
    data_io.write(struct.pack('<QI',  0x0, filesize_count_offset))

    print("tell=%d, index_size=%d"%(data_io.tell(), index_size)) 
    print("writing index area finished with %d entries!"%len(filelist))

    # adding files
    for name, _ in filelist:
        with open(os.path.join(basepath, name), 'rb') as fp:
            data_io.write(fp.read())
            print("copy file %s finished!"% os.path.join(basepath, name))

    # encrypt files' content
    data = data_io.getbuffer()
    pf8 = parsepf8(data)
    key = makekeypf8(pf8)
    print("sha1 hash key is " + key.hex())
    count = pf8['index_count']
    file_entrys = pf8['file_entrys']
    re_unencrpted = []
    for t in unencrpted_filter:
        re_unencrpted.append(re.compile(t))
    for i in range(count):
        path = file_entrys[i]['name'].strip('\0')
        offset = file_entrys[i]['offset']
        size = file_entrys[i]['size']
        encrypted = True
        for  t in re_unencrpted:
            if t.search(path, re.IGNORECASE): 
                encrypted = False
                break
        if encrypted:
            encryptpf8(data, offset, size, key)
            print("%s is encrypted at 0x%X, size %d"%(path, offset, size))
    return data

def unpackpf8(inpath, outpath, 
    unencrpted_filter=[r'\.mp4$', r'\.flv$'], 
    pathlist=None):

    fp = os.open(inpath, os.O_BINARY | os.O_RDONLY) 
    data = mmap.mmap(fp, 0, access=mmap.ACCESS_READ)
    pf8 = parsepf8(data)
    key = makekeypf8(pf8)
    count = pf8['index_count']
    file_entrys = pf8['file_entrys']

    re_unencrpted = []
    for t in unencrpted_filter:
        re_unencrpted.append(re.compile(t))
    for i in range(count):
        path = file_entrys[i]['name'].strip('\0')
        if pathlist is not None and path not in pathlist:
            print("skiped!", path)
            continue
        offset = file_entrys[i]['offset']
        size = file_entrys[i]['size']
        encrypted = True
        for  t in re_unencrpted:
            if t.search(path, re.IGNORECASE): 
                encrypted = False
                break

        if encrypted:
            buf = decryptpf8(data, offset, size, key)
        else:
            buf = data[offset:offset+size]

        fullpath = os.path.join(outpath, path)
        basepath = os.path.dirname(fullpath)
        if not os.path.exists(basepath):
            os.makedirs(basepath)
        with open(fullpath, 'wb') as fp2:
            fp2.write(buf)
        print("%s, offset=0x%X size=%d extracted"%(path, offset, size))
    os.close(fp)

def packpf8(inpath, outpath, unencrpted_filter=[r'\.mp4$', r'\.flv$']):
    filelist=[]
    for root, _, files in os.walk(inpath):
        for file in files:
            filepath = os.path.join(root, file)
            name = os.path.relpath(filepath, inpath)
            size = os.path.getsize(filepath)
            filelist.append((name, size))
            # print("%s %d bytes"%(name, size))
    data = makepf8archive(inpath, filelist, unencrpted_filter)
    if data is None: print("build pf8 archive file failed!")
    else: 
        with open(outpath, 'wb') as fp:
            fp.write(data)

def test1(path1, path2):
    with open(path1, 'rb') as fp:
        data = fp.read()
    pf8 = parsepf8(data)
    pathlist = [x['name'].strip('\0') for x in pf8['file_entrys']]
    unpackpf8(path2, "out", pathlist=pathlist)
    print(pathlist)

def debug():
    test1("xxx_org.pfs", "xxx.pfs")

def main():
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group()
    group.add_argument('-u', "--unpack", type=str)
    group.add_argument('-p', "--pack", type=str)
    parser.add_argument('-o',"--outpath", type=str, default="out")
    args = parser.parse_args()
    # print(args.unpack, args.pack, args.outpath)
    if args.unpack: unpackpf8(args.unpack, args.outpath)
    elif args.pack: packpf8(args.pack, args.outpath)
    else: print("pf8tool argument error!")

if __name__ == "__main__":
    main()
    # debug()
    pass