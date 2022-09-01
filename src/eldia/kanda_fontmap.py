""" 
make the fontmap to gb2312 and patch sjis char check
tested in Kanda Alice switch version,
    v0.1 developed by devseed
"""

import os
import sys
import struct
import mmap
import lief
from keystone import Ks, KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN

# offset for main v1.01
g_fontmap_offset = 0x14aac9 
g_fontmap_length = 9400*2
g_sjistoutf16_offset = 0x6b31 
g_FontIsSjis_offset = 0xc721 # 08 1C 00 13  not use
g_ReadNextCharSjis_offset = 0x99431 # 09 00 40 F9 28 01 40 39 not
g_FONT_GetSjisByMapUV = 0xa691 # E9 03 1F AA E8 80 10 B0 not use

def generate_gb2312_tbl_full():
    tbl = []
    for high in range(0xa1, 0xff): # Chinese charactor
        for low in range(0xa1, 0xff):
            charcode = struct.pack('<BB', high, low)
            try: 
                c = charcode.decode('gb2312')
            except:
                c = '·'
            tbl.append((charcode, c))
    print("gb2312 tbl with " + str(len(tbl)) + " generated!")
    return tbl

def read_unicode_map(data, offset, length, byteorder='little'):
    wchars = []
    for i in range(offset, offset+length, 2):
        wchar = chr(int.from_bytes(data[i:i+2], byteorder))
        wchars.append(wchar)
    return wchars

def write_unicode_map(data, offset, wchars, 
            byteorder='little', allocnew=True):
    if allocnew: data = bytearray(data)
    for i, wchar in enumerate(wchars):
        data[offset+i*2: offset+i*2+2] = int.to_bytes(ord(wchar), 2, byteorder)
    return data

def print_unicodes_sjis(wchars, encoiding='sjis'):
    for i, wchar in enumerate(wchars):
        try:
            sjiscode = wchar.encode(encoiding)
            print(f'{i:04d}', wchar, hex(ord(wchar)), [hex(x) for x in list(sjiscode)])
        except:
            print(f'{i:4d}', ' ', hex(ord(wchar)), ' ')
    pass 

def get_func_code(libpath, func_name):
    bin = lief.parse(libpath)
    func_symbol = bin.get_symbol(func_name)
    code = bin.get_content_from_virtual_address(func_symbol.value, func_symbol.size)
    return bytes(code)

def nop_func(data, offset):
    ks = Ks(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN)
    code, _ = ks.asm("ret")
    data[offset: offset+len(code)] = code

def patch_code(data, offset, code):
    data[offset:offset+len(code)] = code

def patch_sjis_check(data):
    ks = Ks(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN)
    nop, _ = ks.asm("nop")
    print("patching sjis check...")
    
    # FONT_CreateEx, 
    # BC11h .text:000000710000BB10 E9 01 00 54 B.LS            loc_710000BB4C
    # .text:000000710000BB14 88 82 01 11 ADD W8, W20, #0x60 ;
    patch_code(data, 0xBC11, nop)

    # BC25h .text:000000710000BB24 C3 01 00 54 B.CC            loc_710000BB5C
    # .text:000000710000BB28 89 07 40 39 LDRB  W9, [X28,#1] ; w9 second_byte
    patch_code(data, 0xBC25, nop)


def rebuild_main_fontmap(data, tbl, fontmap_offset, fontmap_length):
    wchars = read_unicode_map(data, fontmap_offset, fontmap_length)
    for i in range(len(wchars)):
        if i>=len(tbl): break
        wchars[i] = tbl[i][1]
    return write_unicode_map(data, fontmap_offset, wchars) 

def rebuild_main_func(libpath, func_name, data, offset):
    code = get_func_code(libpath, func_name)
    patch_code(data, offset, code)
    print([hex(x) for x in list(code)])
    print("Func %s injected %d bytes to %x,"%(func_name,len(code), offset))

def rebuild_main(mainpath, libpath, outpath): 
    fd = os.open(mainpath, os.O_RDONLY)
    data = mmap.mmap(fd, 0, access=mmap.ACCESS_READ)
    
    # rebuild fontmap
    tbl = generate_gb2312_tbl_full()
    data2 = rebuild_main_fontmap(data, tbl,g_fontmap_offset, g_fontmap_length)
    
    # rebuild functions
    rebuild_main_func(libpath, "ConvertGb2312ToUtf16", data2, g_sjistoutf16_offset)
    patch_sjis_check(data2)

    with open(outpath, 'wb') as fp:
        fp.write(data2)
        print("save rebuild main to", outpath)
    os.close(fd)
    pass

def debug():
    rebuild_main(r"./build/intermediate/origin/main_v1.01", 
        r"./build/libkanda_fontmap.so", r"./build/main")
    pass

def main():
    if len(sys.argv) < 4:
        print("kanda_fontmap main libkanda_fontmap main_rebuild")
        return
    rebuild_main(sys.argv[1], sys.argv[2], sys.argv[3])

if __name__ =="__main__":
    #debug()
    main()
    pass