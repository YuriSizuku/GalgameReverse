"""
to export or import sn.bin (after extract) text for Narcissus psp, 
  v0.1, developed by devseed
"""

import os
import sys

sys.path.append(os.path.join(os.path.dirname(__file__), r"compat"))
import bintext_v580 as bintext

def export_sntext(inpath, outdir="./out"):
    pass

def import_sntext(inpath, orgpath, tblpath, outpath="out.bin"):
    def _makejumpentry(data, addr):
        jumpto = int.from_bytes(
            data[addr: addr+4], 'little', signed=False)
        jumpentry = {
            'addr': addr, 'jumpto': jumpto, 
            'addr_new': addr, 'jumpto_new': jumpto
        }
        return jumpentry

    def _makejumptable(data):
        jump_table = []
        end = int.from_bytes(data[0:4], 'little', signed=False)
    
        # index offset
        cur = 4
        while cur < end:
            addr = cur # index offsets
            jumpentry = _makejumpentry(data, addr)
            jump_table.append(jumpentry)
            cur += 4
        
        # XX XX 00 79 [addr1 4] XX [addr2 4]
        cur = data.find(b'\x00\x79', end)
        while cur > 0:
            addr = cur + 2
            jumpentry = _makejumpentry(data, addr)
            if jumpentry['jumpto'] < len(data):
                jump_table.append(jumpentry)
                addr = cur + 7
                jumpentry =_makejumpentry(data, addr)
                jump_table.append(jumpentry)
            cur = data.find(b'\x00\x79', cur + 11)
        
        # XX XX 2E 79 [addr1 4] XX [addr2 4]
        cur = data.find(b'\x2e\x79', end)
        while cur > 0:
            addr = cur + 2
            jumpentry = _makejumpentry(data, addr)
            if jumpentry['jumpto'] < len(data):
                jump_table.append(jumpentry)
                addr = cur + 7
                jumpentry =_makejumpentry(data, addr)
                jump_table.append(jumpentry)
            cur = data.find(b'\x2e\x79', cur + 11)
        
        # 07 XX XX 07 00 [addr 4]
        cur = data.find(b'\x07\x00', end)
        while cur > 0:
            if cur - 3 < end or data[cur-3] != 0x07:
                cur = data.find(b'\x07\x00', cur + 2)
            else:
                addr = cur + 2
                jumpentry = _makejumpentry(data, addr)
                jump_table.append(jumpentry)
                cur = data.find(b'\x07\x00', cur + 7)

        # 31 80 80 [opntion_count 4] 
        # [id 4] FF FF [addr1 4] [text1 00]
        # [id 4] FF FF [addr2 4] [text2 00]
        cur = data.find(b'\x31\x80\x80', end)
        while cur > 0:
            cur += 3
            n = int.from_bytes(data[cur: cur+4], 'little', signed=False)
            for i in range(n):
                cur = data.find(b'\xff\xff', cur + 4)
                if cur < 0 or cur + 6 > len(data) : break
                cur += 2
                jumpentry = _makejumpentry(data, cur)
                jump_table.append(jumpentry)
            cur = data.find(b'\x31\x80\x80', cur + 4)

        # FF FF FF FF 01 [addr 4]
        cur = data.find(b'\xFF\xFF\xFF\xFF\x01', end)
        while cur > 0 and cur + 5 < len(data):
            cur += 5
            jumpentry = _makejumpentry(data, cur)
            jump_table.append(jumpentry)
            cur = data.find(b'\xFF\xFF\xFF\xFF\x01', cur+4)

        # FF FF FF FF 79 [addr 4] 01 [addr 4]
        cur = data.find(b'\xFF\xFF\xFF\xFF\x79', end)
        while cur > 0 and cur + 5 < len(data):
            cur += 5
            jumpentry = _makejumpentry(data, cur)
            jump_table.append(jumpentry)
            cur += 4
            if data[cur] == 0x01:
                cur += 1
                jumpentry = _makejumpentry(data, cur)
                jump_table.append(jumpentry)
                cur += 4
            cur = data.find(b'\xFF\xFF\xFF\xFF\x79', cur)

        # 06 94 80 [unknow 2] [addr1 4] 01 [addr 4]
        cur = data.find(b'\x06\x94\x80', end)
        while cur > 0 and cur + 5 < len(data):
            cur += 5
            jumpentry = _makejumpentry(data, cur)
            jump_table.append(jumpentry)
            cur += 4
            if data[cur] == 0x01:
                cur += 1
                jumpentry = _makejumpentry(data, cur)
                jump_table.append(jumpentry)
                cur += 4
            cur = data.find(b'\x06\x94\x80', cur)

        return jump_table
        
    with open(orgpath, 'rb') as fp:
        data = bytearray(fp.read())
    
    jump_table = _makejumptable(data)
    data = bintext.patch_ftextobj(
        inpath, data, "", tblobj=tblpath,
        can_longer=True, can_shorter=True,
        replace_map={"―": "ー", '〜':'～', '─':'～', '—':'～', '漉':'鹿','·':'.', '霾':'狸'}, padding_bytes=b'\x20', 
        jump_table=jump_table)
    for t in jump_table:
        addr_new = t['addr_new']
        jumpto_new = t['jumpto_new']
        data[addr_new: addr_new+4] = int.to_bytes(
            jumpto_new, 4, 'little', signed=False) 

    if outpath!="":
        with open(outpath, 'wb') as fp:
            fp.write(data)
    return data

def debug():
    import_sntext("./build/intermediate/sn_ftext/sn_04.bin.txt", "./build/intermediate/sn/sn_04.bin", "./build/intermediate/font/font_chs.tbl", "./build/intermediate/sn_rebuild/sn_04.bin")
    pass

def main():
    if len(sys.argv) < 3:
        print("Narcissus_sntext e inpath [outpath]")
        print("Narcissus_sntext i inpath orgpath tblpath [outpath]")
        return
    if sys.argv[1].lower() == 'e':
        outpath = sys.argv[3] if len(sys.argv) > 3 else "out.txt"
        export_sntext(sys.argv[2], outpath)
    elif sys.argv[1].lower() == 'i':
        outpath = sys.argv[5] if len(sys.argv) > 5 else "out.bin"
        import_sntext(sys.argv[2], sys.argv[3], sys.argv[4], outpath)
    else: raise ValueError(f"unknow format {sys.argv[1]}")

if __name__ == '__main__':
    # debug()
    main()
    pass