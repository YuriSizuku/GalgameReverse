"""
    for BaranoKiniBaranoSaku psp,  
    analyze the opcode and text in vmc
    v0.1, developed by devseed
"""

import os
import sys
from io import BytesIO


sys.path.append(os.path.join(os.path.dirname(sys.argv[0]), r"compat"))
import bintext_v440 as btext

def print_vmc(path, offset_text=0x34a20): # for op.vmc
    with open(path, 'rb') as fp:
        data = fp.read()
    fsize = os.path.getsize(path)
    idx = 0
    start = 0
    tmpstr = "0x0: "
    text_addrs = []
    text_addr = 0
    for i in range(0, offset_text, 4): # print variable length opcode 
        buf = data[i:i+4]
        d = int.from_bytes(buf, 'little')
        if d*4 + 8 >= offset_text and d*4 + 8 <= fsize: 
            text_addr = 4*d+8
            text_addrs.append(text_addr)
            tmpstr += hex(d)+"("+hex(text_addr)+") "
        else: 
            tmpstr += hex(d) +" "
        if d==0:
            text = ""
            if text_addr!=0:
                try:
                    text += '"'
                    end = data.find(b'\x00', text_addr)
                    text += data[text_addr:end].decode('sjis')
                    text = text.replace('\r', '\\r').replace('\n', '\\n')
                    text += '"'
                except UnicodeDecodeError:
                    text=""
            print(tmpstr+text)
            text_addr = 0
            tmpstr = hex(i)+": "
    
    print("===================================================")
    for addr in text_addrs: # print the text in game sequence
        try:
            end = data.find(b'\x00', addr)
            text = data[addr:end].decode('sjis')
        except UnicodeDecodeError:
            print(i, 'sjis error')
        text = text.replace('\r', '\\r').replace('\n', '\\n')
        print(hex(addr), hex(end-addr), text)
    
    print("===================================================")
    for i in range(offset_text, len(data)): # print the text in original sequence
        if data[i]==0:
            if start==0: continue
            else:
                try:
                    text = data[start:i].decode('sjis')
                except UnicodeDecodeError:
                    print(i, 'sjis error')
                text = text.replace('\r', '\\r').replace('\n', '\\n')
                print(idx, hex(start), i-start, hex(i-start), text)
                idx += 1
                start = 0
        else:
             if start==0: start = i

def get_vmc_opcode(data):
    opcodes = [{'addr':0, 'opcode':[]}] 
    for i in range (0, len(data), 4):
        d = int.from_bytes(data[i:i+4], 'little')
        opcodes[-1]['opcode'].append(d)
        if d == 0:
            opcodes.append({'addr':i+4, 'opcode':[]})
    return opcodes

def export_vmc_text(vmcpath, outpath):
    print("To export "+vmcpath+" ...")
    with open(vmcpath, 'rb') as fp:
        data = fp.read()
    opcodes = get_vmc_opcode(data)
    ftexts = []
    for i, t in enumerate(opcodes):
        if len(t['opcode']) == 8 and t['opcode'][0]==3 and t['opcode'][-2] == 0x22220001: # text
            text_addr = t['opcode'][1]*4+8
            j = text_addr
            while data[j]!=0: j+=1
            text = data[text_addr:j].decode('sjis')
            text = text.replace("\n", "[\\n]").replace("\r", "[\\r]")
            ftexts.append({'addr':text_addr, 'size': j-text_addr, 'text':text})
            print(i, hex(t['addr']), hex(text_addr), text.replace(r"[\r][\n]", "")[0:10]+"...", "extracted!")
    btext.write_format_text(outpath, ftexts, ftexts)

def import_vmc_text(vmcpath, textpath, outpath, tblpath=""):
    if tblpath!="": tbl = btext.load_tbl(tblpath)
    else: tbl=None
    print("To import in "+vmcpath+" ...")
    with open(vmcpath, 'rb') as fp:
        data = bytearray(fp.read())
    _, ftexts = btext.read_format_text(textpath)
    ftexts.sort(key=lambda t:t['addr'])

    # find all text in text_map
    text_map = {} # {addr:text_data}
    text_start_addr = ftexts[0]['addr']
    print(f"text_start_addr=0x{text_start_addr:x}")

    i = text_start_addr
    while i < len(data):
        j = i
        while data[j]!=0: j+=1
        text_map.update({i:data[i:j]})
        while j < len(data) and data[j]==0 : j+=1
        i = j

    # find all text references addr in text_ref_map
    text_ref_map =dict() # {text_addr:[opcode_addr1, ...]}
    opcodes = get_vmc_opcode(data)
    for i, t in enumerate(opcodes):
        # 0x198b4: 0x3 0xfdad(0x3f6bc) 0x2 0x12 0x2 0x3 0x4 0x0 "my270033"
        if len(t['opcode']) == 8 and t['opcode'][0]==3:
            if t['opcode'][-2] == 0x12 or  \
                t['opcode'][-2] == 0xa or \
                t['opcode'][-2] == 0x4 or \
                t['opcode'][-2] == 0x22220001:

                addr = t['opcode'][1] * 4 + 8
                # print(i, hex(addr))
                text_ref_addr = t['addr'] + 4
                if addr >= text_start_addr:
                    if addr not in text_ref_map.keys():
                        text_ref_map.update({addr:[text_ref_addr]})
                    else: # it might have multi results!
                        text_ref_map[addr].append(text_ref_addr)              

    # import and rebuild the vmc script
    for i, t in enumerate(ftexts): 
        addr = t['addr']
        text = t['text'].replace('[\\n]', '\n').replace('[\\r]', '\r')
        if tbl is None:
            text_data = text.encode('sjis')
        else:
            text_data = bytearray()
            j = 0
            while j<len(text):
                pos = text.find("\r\n", j) # this seperate the line
                if pos==0:
                    text_data += b"\r\n"
                    j += 2
                elif pos!=-1: # because font use utf-16...
                    text_data += btext.encode_tbl(text[j:pos], tbl) + b"\r\n"
                    j = pos + 2
                else:
                    text_data += btext.encode_tbl(text[j:], tbl)
                    break 
        text_map.update({addr:text_data})
    
    # write rebuild all texts and indexs
    data_rebuild =  BytesIO()
    for k in sorted(text_map.keys()):# 4 byte align is troublesome
        text_data = text_map[k] # k org text addr
        for text_ref_addr in text_ref_map[k]:
            idx_rebuild = (data_rebuild.tell() + text_start_addr - 8)//4
            data_rebuild.write(text_data)
            n = 4-(data_rebuild.tell()+text_start_addr)%4
            data_rebuild.write(n * b'\x00') 
            if idx_rebuild*4+8 != k:
                data[text_ref_addr:text_ref_addr+4] = int.to_bytes(idx_rebuild, 4, 'little')
                print("rebuild index 0x%x, 0x%x(0x%x) -> 0x%x(0x%x)" % 
                        (text_ref_addr, (k-8)//4, k, 
                        idx_rebuild, idx_rebuild*4+8))

    with open(outpath, 'wb') as fp:
        fp.write(data[0:text_start_addr])
        fp.write(data_rebuild.getbuffer())
                
def main():
    if len(sys.argv) <= 2:
        print(r"vmc e vmcpath [outpath] //export xxx.vmc text:")
        print(r"vmc i vmcpath textpath tblpath [outpath] //import text into xxx.vmc")
    ext = sys.argv[2].split('.')[-1]
    if sys.argv[1].lower() == 'e':   
        vmcpath = sys.argv[2]
        if len(sys.argv) <= 3: outdir = vmcpath + '.txt'
        else: outdir = sys.argv[3]
        export_vmc_text(vmcpath, outdir)
    elif sys.argv[1].lower() == 'i':
        vmcpath = sys.argv[2]
        textpath = sys.argv[3]
        tblpath = sys.argv[4]
        if len(sys.argv) == 5: outpath = os.path.splitext(textpath)[0] + '.vmc'
        else: outpath = sys.argv[5]
        import_vmc_text(vmcpath, textpath, outpath, tblpath=tblpath)
    else: print("invalid arguemnts!")

def debug():
    basedir = "./build/intermediate"
    #print_vmc(os.path.join(basedir, "./vmc/special.vmc"))
    import_vmc_text(os.path.join(basedir, "./vmc/special.vmc"), 
        os.path.join(basedir, "./vmc_chs/special.vmc.txt"),
        os.path.join(basedir, "./vmc_rebuild/special.vmc"),
        os.path.join(basedir, "MINTYOU16_rebuild.FNT.tbl"))
    print_vmc(os.path.join(basedir, "./vmc_rebuild/special.vmc"))
    pass

if __name__ == "__main__":
    #debug()
    main()
    pass