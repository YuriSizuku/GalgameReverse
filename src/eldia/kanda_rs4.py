""" 
parse rs4 file for importing text 
tested in Kanda Alice switch version,
    v0.1 developed by devseed

if some keyerror occured in textaddr_map[ftext['addr']]
delete the none text entry will pass
(becasue it was exported by all sjis likely)
"""

import os
import sys
import copy
import struct
import mmap

sys.path.append(r".\..\..\util\script")
try:
    import zbintext_v043 as bintext
except:
    import bintext

def parse_rs4(data):
    """
    rs4_header:  
    0X0~0x10 RS4 00 [version 4]  00 00 00 00 00 00 00 00
    0x10~0x20 [opcode_size 4] [text_size 4] [text_table_size 4] 00 00 00 00 
    // 01a_00001.bin , 0x4f60, item_count 0xc0

    text_offset_table: // in the end of the rs4 file
    |text_item_offset[] 4 // offset from text_block_offset
    :return: rs4_header {magic:, version:, opcode_size, text_size:, text_table_size:},  
             text_offset_table[]
    """

    rs4_header = {}
    textoff_table = []
    rs4_header['magic'] = data[0:4]
    rs4_header['version'] = int.from_bytes(data[4:8], 'little')
    rs4_header['opcode_size'], rs4_header['text_size'], rs4_header['text_table_size']= struct.unpack("<III", data[0x10:0x1c])

    cur_offset = 0x20
    opcode_data = data[cur_offset: cur_offset+ rs4_header['opcode_size']]

    cur_offset = 0x20 + rs4_header['opcode_size'] + rs4_header['text_size']
    for i in range(0, rs4_header['text_table_size'], 4):
        d = int.from_bytes(data[cur_offset+i: cur_offset+i+4], 'little')
        textoff_table.append(d)

    cur_offset = 0x20 + rs4_header['opcode_size']
    texts_data = []
    start = textoff_table[0]
    for i in range(1, len(textoff_table)):
        if i!=0 and textoff_table[i]==0: break # end 0 padding
        end = textoff_table[i]
        texts_data.append(data[cur_offset+start: cur_offset+end])
        start = end
    end = rs4_header['text_size']
    texts_data.append(data[cur_offset+start: cur_offset+end])

    return rs4_header, opcode_data, texts_data, textoff_table

def rebuild_rs4_index(rs4_header, opcode_data, 
    texts_data, textoff_table):
    
    rs4_header_rebuild = copy.deepcopy(rs4_header)
    textoff_table_rebuild = copy.deepcopy(textoff_table)
    texts_data_rebuild = []

    cur = 0
    for i, _ in enumerate(texts_data):
        text_data_rebuild = texts_data[i].rstrip(b'\x00')
        text_data_rebuild += b'\x00' * (0x10 - len(text_data_rebuild) % 0x10)
        texts_data_rebuild.append(text_data_rebuild)
        textoff_table_rebuild[i] = cur
        cur += len(text_data_rebuild)

    rs4_header_rebuild['text_size'] = cur

    return rs4_header_rebuild, texts_data_rebuild, textoff_table_rebuild

def write_rs4(outpath, rs4_header, opcode_data, 
    texts_data, text_offset_table):

    with open(outpath, 'wb') as fp:
        fp.write(rs4_header['magic'])
        fp.write(int.to_bytes(rs4_header['version'], 4, 'little'))
        fp.write(b'\x00' * 8)
        fp.write(struct.pack('<III', rs4_header['opcode_size'], rs4_header['text_size'], rs4_header['text_table_size']))
        fp.write(b'\x00' * 4)
        
        fp.write(opcode_data)
        for text_data in texts_data:
            fp.write(text_data)
    
        for offset in text_offset_table:
            fp.write(int.to_bytes(offset, 4, 'little'))

def import_rs4(inpath, ftextpath, outpath="out.bin", encoding='gbk'):
    ftexts = bintext.read_format_text(ftextpath)
    fd = os.open(inpath, os.O_RDONLY)
    data = mmap.mmap(fd, 0, access=mmap.ACCESS_READ)
    rs4_header, opcode_data, texts_data, textoff_table = parse_rs4(data)
    print("insert text to %s, with %d ftexts"%(inpath, len(ftexts[1])))
    
    textaddr_map = {} # offset:idx
    textoff_start = 0x20 + rs4_header['opcode_size']
    for i, offset in enumerate(textoff_table):
        if i!=0 and offset==0: break # end 0 padding
        textaddr_map.update({textoff_start + offset: i})
    for ftext in ftexts[1]:
        idx = textaddr_map[ftext['addr']]
        texts_data[idx] = ftext['text'].encode(encoding)
    
    rs4_header_rebuild, texts_data_rebuild, textoff_table_rebuild = rebuild_rs4_index(rs4_header, opcode_data, texts_data, textoff_table)
    write_rs4(outpath, rs4_header_rebuild, opcode_data, texts_data_rebuild, textoff_table_rebuild)
    os.close(fd)

def debug():
    basedir = "./build/intermediate/"
    filename = "01a_05000.bin"
    import_rs4(
        os.path.join(basedir, "./origin/01_script/", filename), 
        os.path.join(basedir, './script_chs/', filename+'.txt'))
    with open('out.bin', 'rb') as fp:
        data = fp.read()
    parse_rs4(data)
    pass

def main():
    if len(sys.argv) < 4:
        print("rs4 i rs4path ftextpath [outpath]")
        return
    if sys.argv[1].lower() == 'i':
        inpath = sys.argv[2]
        ftextpath = sys.argv[3]
        outpath = sys.argv[4] if len(sys.argv) > 4 else "out.bin"
        import_rs4(inpath, ftextpath, outpath)
    else:
        print("unsupport argument: ", sys.argv[1])

if __name__ =="__main__":
    #debug()
    main()
    pass
