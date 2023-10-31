"""
export or import spt text for systemNNN, 
  v0.1, developed by devseed

tested game:
  倭人異聞録～あさき、ゆめみし～

"""

import re
import sys
import math
import codecs
import struct
import argparse
from io import BytesIO
from enum import Enum
from collections import namedtuple
from typing import Union, List, Dict

# util functions
def dump_ftext(ftexts1:List[Dict[str,Union[int,str]]], 
    ftexts2: List[Dict[str, Union[int, str]]], 
    outpath: str="", *, num_width=5, 
    addr_width=6, size_width=3) -> List[str]:
    """
    ftexts1, ftexts2 -> ftext lines
    text dict is as {'addr':, 'size':, 'text':}
    :param ftexts1[]: text dict array in '○' line, 
    :param ftexts2[]: text dict array in '●' line
    :return: ftext lines
    """

    if num_width==0:
        num_width = len(str(len(ftexts1)))
    if addr_width==0:
        d = max([t['addr'] for t in ftexts1])
        addr_width = len(hex(d)) - 2
    if size_width==0:
        d = max([t['size'] for t in ftexts1])
        size_width = len(hex(d)) - 2

    fstr1 = "○{num:0"+ str(num_width) + "d}|{addr:0" + str(addr_width) + "X}|{size:0"+ str(size_width) + "X}○ {text}\n"
    fstr2 = fstr1.replace('○', '●')
    lines = []

    length = 0
    if ftexts1 == None: 
        length = len(ftexts2)
        fstr2 += '\n'
    if ftexts2 == None: 
        length = len(ftexts1)
        fstr1 += '\n'
    if ftexts1 != None and ftexts2 != None : 
        length = min(len(ftexts1), len(ftexts2))
        fstr2 += '\n'

    for i in range(length):
        if ftexts1 != None:
            t1 = ftexts1[i]
            lines.append(fstr1.format(
                num=i,addr=t1['addr'],size=t1['size'],text=t1['text']))
        if ftexts2 != None:
            t2 = ftexts2[i]
            lines.append(fstr2.format(
                num=i,addr=t2['addr'],size=t2['size'],text=t2['text']))

    if outpath != "":
        with codecs.open(outpath, 'w', 'utf-8') as fp:
            fp.writelines(lines)
    return lines 

def load_ftext(ftextobj: Union[str, List[str]], 
    only_text = False ) -> List[Dict[str, Union[int, str]]]:
    """
    ftext lines  -> ftexts1, ftexts2
    text dict is as {'addr':, 'size':, 'text':}
    :param inobj: can be path, or lines[] 
    :return: ftexts1[]: text dict array in '○' line, 
             ftexts2[]: text dict array in '●' line
    """

    ftexts1, ftexts2 = [], []
    if type(ftextobj) == str: 
        with codecs.open(ftextobj, 'r', 'utf-8') as fp: 
            lines = fp.readlines()
    else: lines = ftextobj

    if only_text == True: # This is used for merge_text
        re_line1 = re.compile(r"^○(.+?)○[ ](.*)")
        re_line2 = re.compile(r"^●(.+?)●[ ](.*)")
        for line in lines:
            line = line.strip("\n").strip('\r')
            m = re_line1.match(line)
            if m is not None:
                ftexts1.append({'addr':0,'size':0,'text': m.group(2)})
            m = re_line2.match(line)
            if m is not None:
                ftexts2.append({'addr':0,'size':0,'text': m.group(2)})
    else:
        re_line1 = re.compile(r"^○(\d*)\|(.+?)\|(.+?)○[ ](.*)")
        re_line2 = re.compile(r"^●(\d*)\|(.+?)\|(.+?)●[ ](.*)")
        for line in lines:
            line = line.strip("\n").strip('\r')
            m = re_line1.match(line)
            if m is not None:
                ftexts1.append({'addr':int(m.group(2),16),
                'size':int(m.group(3),16),'text': m.group(4)})
            m = re_line2.match(line)
            if m is not None:
                ftexts2.append({'addr':int(m.group(2),16),
                'size':int(m.group(3),16),'text': m.group(4)})
    return ftexts1, ftexts2

class struct_t(struct.Struct):
    """
    base class for pack or unpack struct, 
    _ for meta info, __ for internal info
    """
    
    def __init__(self, data=None, cur=0, *, fmt=None, names=None) -> None:
        """"
        _meta_fmt: struct format
        _meta_names: method names 
        """

        if not hasattr(self, "_meta_names"): self._meta_names = []
        if not hasattr(self, "_meta_fmt"): self._meta_fmt = ""
        if names: self._meta_names = names
        if fmt: self._meta_fmt = fmt
        super().__init__(self._meta_fmt)
        if data: self.frombytes(data, cur)

    def cppinherit(self, fmt, names):
        if not hasattr(self, "_meta_names"): self._meta_names = names
        else: self._meta_names =  names + self._meta_names
        if not hasattr(self, "_meta_fmt"): self._meta_fmt = fmt
        else: self._meta_fmt += fmt.lstrip('<').lstrip('>')
        
    def frombytes(self, data, cur=0, *, fmt=None) -> None:
        if fmt: vals = struct.unpack_from(fmt, data, cur)
        else: vals = self.unpack_from(data, cur)
        names = self._meta_names
        for i, val in enumerate(vals):
            if i >= len(names): break
            setattr(self, names[i], val)
        self._data = data
    
    def tobytes(self, *, fmt=None) -> bytes:
        vals = []
        names = self._meta_names
        for name in names:
            vals.append(getattr(self, name))
        if fmt: _data = struct.pack(fmt, *vals)
        else: _data = self.pack(*vals)
        return _data

# spt types
"""
spt header:
0x10 msg_count1 4, msg_ptr1 4, msg_count2 4, msg_ptr2 4, 
0x50 subcall_ptr 4, select_ptr 4, cmdcall_ptr 4, scriptcall_ptr 4

spt opcode: 
[op_params 4] [op_id 4] [op_code 4]  // whole params , IDENTIFY_, CODE_DATA_
... [msg_ptr 4] [msgpre_ptr 4] [cutin 4]// CODE_SYSTEMCOMMAND_PRINT
... [sel_count 4] [sel_ptrs 4*n] // CODE_SYSTEMCOMMAND_SELECT
    [timelimit 4, autoselect 4, specialflag 4, selectserial 4] [mes_count 4]

"""

class SPT_ID(Enum):
    IDENTIFY_DATA=0x66660001
    IDENTIFY_CONTROL=0x66660002
    IDENTIFY_COMMAND=0x66660003
    IDENTIFY_FUNCTION=0x66660004
    IDENTIFY_CALCU=0x66660005
    IDENTIFY_SYSTEMCOMMAND=0x66660006
    IDENTIFY_SYSTEMFUNCTION=0x066660007

class SPT_CODE(Enum):
    CODE_DATA_HEADER0=0x55550001
    CODE_DATA_TABLE=0x55550002
    CODE_DATA_LABEL=0x55550003
    CODE_DATA_FILMLABEL=0x55550004
    CODE_CONTROL_NOP=0x55560001
    CODE_CONTROL_IF=0x55560002
    CODE_CONTROL_ELSIF=0x55560003
    CODE_CONTROL_ELSE=0x55560004
    CODE_CONTROL_END=0x55560005
    CODE_CONTROL_NEXT=0x55560006
    CODE_CONTROL_RETURN=0x55560007
    CODE_CONTROL_CASE=0x55560008
    CODE_CONTROL_SUB=0x55560009
    CODE_CONTROL_SCRIPT=0x5556000a
    CODE_CONTROL_EXIT=0x5556000b
    CODE_CONTROL_ENDFILM=0x5556000c
    CODE_CONTROL_STARTMESSAGE=0x5556000d
    CODE_CONTROL_ENDKOMA=0x5556000e
    CODE_CONTROL_WHILE=0x55560011
    CODE_CONTROL_ENDIF=0x55560013
    CODE_CONTROL_SCRIPTJUMP=0x55560015
    CODE_CONTROL_SUBSCRIPT=0x55560016
    CODE_CONTROL_GOTO=0x55560020
    CODE_SYSTEMFUNCTION_MUSIC=0x33330007
    CODE_SYSTEMFUNCTION_VOICE=0x33330008
    CODE_SYSTEMFUNCTION_SOUND=0x33330009
    CODE_SYSTEMFUNCTION_PREPAREOVERRAP=0x33330011
    CODE_SYSTEMFUNCTION_CLEARALLEFFECT=0x33330012
    CODE_SYSTEMFUNCTION_SETEFFECT=0x33330013
    CODE_SYSTEMFUNCTION_CLEAREFFECTLAYER=0x33330014
    CODE_SYSTEMFUNCTION_LOADDWQ=0x33330015
    CODE_SYSTEMFUNCTION_SETEFFECTRECT=0x33330016
    CODE_SYSTEMFUNCTION_NOMESSAGEWINDOW=0x33330017
    CODE_SYSTEMFUNCTION_SETCG=0x33330018
    CODE_SYSTEMFUNCTION_SETSCENE=0x33330019
    CODE_SYSTEMFUNCTION_SETFILM=0x3333001a
    CODE_SYSTEMFUNCTION_STARTMESSAGE=0x3333001b
    CODE_SYSTEMFUNCTION_STARTKOMA=0x3333001c
    CODE_SYSTEMFUNCTION_STARTFILM=0x3333001d
    CODE_SYSTEMFUNCTION_SETDEMOFLAG=0x3333001e
    CODE_SYSTEMFUNCTION_PRELOADDWQ=0x3333001f
    CODE_SYSTEMFUNCTION_FRAMECONTROL=0x33330028
    CODE_SYSTEMFUNCTION_SETDEFAULTFRAME=0x33330029
    CODE_SYSTEMFUNCTION_DEBUG=0x33330042
    CODE_SYSTEMFUNCTION_FILMNAME=0x33330050
    CODE_SYSTEMFUNCTION_STORYNAME=0x33330051
    CODE_SYSTEMFUNCTION_FILMTYPETIME=0x33330052
    CODE_SYSTEMFUNCTION_CONFIGMASK=0x33330053
    CODE_SYSTEMFUNCTION_WINDOWNUMBER=0x33330054
    CODE_SYSTEMFUNCTION_MOUSENUMBER=0x33330055
    CODE_SYSTEMFUNCTION_CURSORNUMBER=0x33330056
    CODE_SYSTEMFUNCTION_AUTOMESSAGE=0x33330057
    CODE_SYSTEMFUNCTION_CANNOTCLICK=0x33330058
    CODE_SYSTEMFUNCTION_CANNOTSKIP=0x33330059
    CODE_SYSTEMFUNCTION_OPTIONOFF=0x3333005a
    CODE_SYSTEMFUNCTION_CUTIN=0x3333005b
    CODE_SYSTEMFUNCTION_MESSAGEEXPSTATUS=0x3333005c
    CODE_SYSTEMFUNCTION_FILMENDENABLE=0x3333005d
    CODE_SYSTEMFUNCTION_FILMEXPSTATUS=0x3333005e
    CODE_SYSTEMFUNCTION_CHANGEMESSAGEFONTSIZETYPE=0x3333005f
    CODE_SYSTEMFUNCTION_RENAMELAYER=0x33330060
    CODE_SYSTEMFUNCTION_SETCGBYVAR=0x33330061
    CODE_SYSTEMFUNCTION_SETVAR=0x33330062
    CODE_SYSTEMFUNCTION_VARCONTROLLAYER=0x33330063
    CODE_SYSTEMFUNCTION_FACE=0x33330064
    CODE_SYSTEMFUNCTION_MUSTFACE=0x33330065
    CODE_SYSTEMFUNCTION_NEXTFADE_SE=0x33330066
    CODE_SYSTEMFUNCTION_NEXTFADE_VOICE=0x33330067
    CODE_SYSTEMFUNCTION_VOLUMEONLY_SE=0x33330068
    CODE_SYSTEMFUNCTION_VOLUMEONLY_VOICE=0x33330069
    CODE_SYSTEMFUNCTION_MUSICVOLUMEONLY=0x3333006a
    CODE_SYSTEMFUNCTION_SETACHIEVEMENT=0x3333006b
    CODE_SYSTEMFUNCTION_SETVOICEFLAG=0x3333006c
    CODE_SYSTEMFUNCTION_SETTERM=0x3333006d
    CODE_SYSTEMFUNCTION_MESSAGEEFFECT=0x3333006e
    CODE_SYSTEMFUNCTION_MESSAGEEFFECTTIME=0x3333006f
    CODE_SYSTEMCOMMAND_PRINT=0x22220001
    CODE_SYSTEMCOMMAND_LPRINT=0x22220002
    CODE_SYSTEMCOMMAND_APPEND=0x22220003
    CODE_SYSTEMCOMMAND_DRAW=0x22220004
    CODE_SYSTEMCOMMAND_OVERRAP=0x22220005
    CODE_SYSTEMCOMMAND_SELECT=0x22220006
    CODE_USERCOMMAND=0x11110001
    CODE_UNKNOW = 0X0

sptheader_t = namedtuple("sptheader_t", ['msg_count1', 'msg_ptr1', 'msg_count2', 'msg_ptr2'])

class sptcmd_t(struct_t):
    def __init__(self, _addr, data=None, cur=0) -> None:
        self.cppinherit("<3I", ['op_params', 'op_id', 'op_code'])
        self._addr = _addr
        self.op_params, self.op_id, self.op_code = [0] * 3        
        super().__init__(data, cur)

class sptcmdmsg_t(sptcmd_t):
    def __init__(self, _addr, data=None, cur=0) -> None:
        self._meta_fmt = "<3I"
        self._meta_names = ["msg_ptr", "msgpre_ptr", "cutin"]
        self.msg_ptr, self.msgpre_ptr, self.cutin = [0] * 3
        super().__init__(_addr, data, cur) 

class sptcmdsel_t(sptcmd_t):
    """
    [op_params 4], [op_id 4], [op_code 4], 
        [sel_count 4], [sel_ptrs 4*n1], [sel_params 4*n2], [mes_count 4] 
    """
    
    def __init__(self, _addr, data=None, cur=0) -> None:
        self.sel_count, self.mes_count,  = 0, 0 
        self.sel_ptrs, self.sel_params = [], []
        super().__init__(_addr, data, cur)

    def frombytes(self, data, cur=0, *, fmt=None) -> None:
        super().frombytes(data, cur, fmt=self._meta_fmt)
        self.sel_count, = struct.unpack_from("<I", data, cur + 4*3)
        self.mes_count, = struct.unpack_from("<I", data, cur + 4*(self.op_params-1))
        nsel = self.sel_count +  self.mes_count
        nselparams = self.op_params - 3 - nsel -2
        self.sel_ptrs = struct.unpack_from(f"<{nsel}I", data, cur + 4*4)
        self.sel_params = struct.unpack_from(f"<{nselparams}I", data, cur + 4*(4+nsel))
    
    def tobytes(self) -> bytes:
        bytes1 = super().tobytes()
        vals = [self.sel_count] + list(self.sel_ptrs) + list(self.sel_params) + [self.mes_count]
        bytes2 = struct.pack(f"<{len(vals)}I", *vals)
        return bytes1 + bytes2

# spt functions
class Spt:
    @classmethod
    def decrypt(cls, data) -> bytes:
        return bytearray(map(lambda x: x ^ 0xff, data))

    @classmethod 
    def encrypt(cls, data) -> bytes:
        return bytearray(map(lambda x: x ^ 0xff, data))
    
    @classmethod
    def decrypt_to(cls, inpath, outpath):
        with open(inpath, 'rb') as fp:
            data = fp.read()
        with open(outpath, 'wb') as fp:
            fp.write(cls.decrypt(data))

    @classmethod
    def encrypt_to(cls, inpath, outpath):
        with open(inpath, 'rb') as fp:
            data = fp.read()
        with open(outpath, 'wb') as fp:
            fp.write(cls.encrypt(data))

    def __init__(self, data=None) -> None:
        self.m_header: sptheader_t
        self.m_cmds: List[Union[sptcmd_t, sptcmdmsg_t, sptcmdsel_t]] = []
        if data: self.parse(data)

    def _text_map(self, encoding="sjis"):
        text_map = {}
        for i, sptcmd in enumerate(self.m_cmds):
            if type(sptcmd) == sptcmdmsg_t:
                msgptr_addr, msg_addr = self.get_msgaddr(sptcmd.msg_ptr)
                text_map.update({msg_addr: 
                    {'ptr_addr': msgptr_addr, 'cmd_idx': i}})
            elif type(sptcmd) == sptcmdsel_t:
                for j in range(sptcmd.sel_count + sptcmd.mes_count):
                    strptr_addr, str_addr = self.get_straddr(sptcmd.sel_ptrs[j])
                    text_map.update({str_addr: 
                        {'ptr_addr': strptr_addr, 'cmd_idx': i, 'sel_idx': j}})
        return text_map

    def get_msgaddr(self, ptr):
        # return (LPSTR)(&m_data[m_data[m_messagePointer1 + mesNum]]);
        msg_ptr = self.m_header.msg_ptr1
        msgptr_addr = (ptr + msg_ptr) * 4
        _ptr, = struct.unpack_from("<I", self.m_data, msgptr_addr)
        msg_addr = _ptr*4
        return msgptr_addr, msg_addr
    
    def get_straddr(self, ptr):
        # return (LPSTR)(&m_data[m_data[m_messagePointer2 + strNum]]);
        str_ptr = self.m_header.msg_ptr2
        strptr_addr = (ptr + str_ptr)*4
        _ptr, = struct.unpack_from("<I", self.m_data, strptr_addr)
        str_addr = _ptr*4
        return strptr_addr, str_addr
    
    def get_text(self, addr, encoding="sjis"):
        end = addr
        while end < len(self.m_data) and self.m_data[end]!=0: end+=1
        text = self.m_data[addr: end].decode(encoding)
        return text, end - addr

    def parse(self, data):
        self.m_data = data
        msg_count1, msg_ptr1, msg_cout1, msg_ptr2 = \
            struct.unpack_from("<4I", data, 0x10)
        self.m_header = sptheader_t(msg_count1, msg_ptr1, msg_cout1, msg_ptr2)

        cur = 0
        sptcmds = self.m_cmds
        while cur < len(data):
            sptcmd = sptcmd_t(cur, data, cur)
            if sptcmd.op_code in {SPT_CODE.CODE_SYSTEMCOMMAND_PRINT.value, 
                    SPT_CODE.CODE_SYSTEMCOMMAND_LPRINT.value, 
                    SPT_CODE.CODE_SYSTEMCOMMAND_APPEND.value} :
                sptcmdmsg = sptcmdmsg_t(cur, data, cur)
                sptcmds.append(sptcmdmsg)
            elif sptcmd.op_code == SPT_CODE.CODE_SYSTEMCOMMAND_SELECT.value:
                sptcmdsel = sptcmdsel_t(cur, data, cur)
                sptcmds.append(sptcmdsel)
            else:
                sptcmds.append(sptcmd)
            cur += sptcmd.op_params * 4

    def append_section(self, section_data) -> bytes:
        sptcmd = sptcmd_t(_addr=len(self.m_data))
        sptcmd.op_params = math.ceil(len(section_data) / 4) + 3
        sptcmd.op_id = SPT_ID.IDENTIFY_DATA.value
        sptcmd.op_code = SPT_CODE.CODE_DATA_TABLE.value
        self.m_cmds.append(sptcmd)
        npadding = (sptcmd.op_params - 3)*4  - len(section_data)
        self.m_data = self.m_data + sptcmd.tobytes() + section_data + bytes([0]*npadding)
        return sptcmd

    def print_cmds(self, encoding="sjis"):
        for i, sptcmd in enumerate(self.m_cmds):
            enum_id = SPT_ID(sptcmd.op_id)
            try:
                enum_code = SPT_CODE(sptcmd.op_code)
            except ValueError:
                enum_code = SPT_CODE(0)

            if type(sptcmd) == sptcmdmsg_t:
                msgptr_addr, msg_addr = self.get_msgaddr(sptcmd.msg_ptr)
                text, _ = self.get_text(msg_addr, encoding)
                print(f"# [msg 0x{msgptr_addr:x}->0x{msg_addr:x}] " + \
                    text.replace('\r', r'[\r]').replace('\n', r'[\n]'))
            elif type(sptcmd) == sptcmdsel_t:
                for j in range(sptcmd.sel_count + sptcmd.mes_count):
                    strptr_addr, str_addr = self.get_straddr(sptcmd.sel_ptrs[j])
                    text, _ = self.get_text(str_addr, encoding)
                    print(f"# [sel{j} 0x{strptr_addr:x}->0x{str_addr:x}] " + \
                        text.replace('\r', r'[\r]').replace('\n', r'[\n]'))

            print(f"[{i}|0x{sptcmd._addr:x}] {sptcmd.op_params}, "
                f"{enum_id.name}({enum_id.value:08x}), "
                f"{enum_code.name}({enum_code.value:08x})")

    def export_ftexts(self, encoding="sjis"):
        text_map = self._text_map(encoding)
        addrs = list(text_map.keys())
        addrs.sort()
        ftexts = []
        for addr in addrs:
            text, size = self.get_text(addr, encoding)
            ftexts.append({'addr': addr, 'size': size, 
                'text': text.replace('\r', r'[\r]').replace('\n', r'[\n]')})
        return ftexts

    def import_ftexts(self, ftexts, encoding="gbk"):
        def _adjust_text(text):
            text = text.replace(r'[\r]', '\r').replace(r'[\n]', '\n')
            if encoding == "gbk":
                text = re.sub("#［(.+?)］", "", text) #［３たいまし］
                replace_map = {"―": "ー", '〜':'~', '─':'-', '—':'-', '～':'~', '・':'.', '≪':'《', '−':'-', '♪':'音'}
                for k, v in replace_map.items():
                    text = text.replace(k, v)

            return text

        def _make_textdata(text):
            textdata = text.encode(encoding) + b'\x00'
            remain_set = {"#名", "#心", "#猫"}
            for v in remain_set:
                textdata = textdata.replace(v.encode(encoding), v.encode('sjis'))
            return textdata
        
        # load ftext and prepare data
        ftext_map = {}
        section_io = BytesIO()
        for ftext in ftexts:
            addr, size = ftext['addr'], ftext['size']
            text = _adjust_text(ftext['text'])
            text_data = _make_textdata(text)
            npaading = 4 - len(text_data) % 4 # 0x4 align
            ftext_map[addr] = section_io.tell()
            section_io.write(text_data + bytes([0] * npaading))
        
        # append data to new section and fix text pointer
        shift = len(self.m_data) + 12
        self.m_data = bytearray(self.m_data)
        self.append_section(section_io.getbuffer())
        text_map = self._text_map(encoding)
        for addr, offset in ftext_map.items():
            ptr_addr = text_map[addr]["ptr_addr"]
            struct.pack_into("<I", self.m_data, 
                ptr_addr, (offset + shift) // 4)
            
def load_spt(inpath) -> Spt:
    with open(inpath, 'rb') as fp:
        data = Spt.decrypt(fp.read())
    return Spt(data)

def print_spt(inpath, encoding='sjis'):
    spt = load_spt(inpath)
    spt.print_cmds(encoding)

def export_spt(inpath, outpath="out.txt", encoding="sjis"):
    spt = load_spt(inpath)
    ftexts = spt.export_ftexts(encoding)
    if outpath: dump_ftext(ftexts, ftexts, outpath)
    return ftexts

def import_spt(inpath, ftextpath, outpath="out.spt", encoding="gbk"):
    spt = load_spt(inpath)
    _, ftexts2 = load_ftext(ftextpath)
    spt.import_ftexts(ftexts2, encoding)
    if outpath: 
        with open(outpath, 'wb') as fp:
            fp.write(Spt.encrypt(spt.m_data))
    return spt.m_data

def debug():
    cmdstr1 = "p build/intermediate/zorigin/spt/0_kyoutuu.spt"
    cmdstr2 = "e build/intermediate/zorigin/spt/0_kyoutuu.spt"\
              "-o build/intermediate/zorigin/spt/0_kyoutuu.spt.txt"
    cmdstr3 = "i build/intermediate/zorigin/spt/0_kyoutuu.spt "\
              "-t build/intermediate/spt_ftext/0_kyoutuu.spt.txt "\
              "-o build/intermediate/spt_rebuild/0_kyoutuu.spt"
    cmdstr4 = "p build/intermediate/spt_rebuild/0_kyoutuu.spt --encoding gbk"
    main(cmdstr3)
    main(cmdstr4)

def main(cmdstr=None):
    if len(sys.argv) < 3 and not cmdstr:
        print("systemnnn_spt p|print [--encoding sjis] inpath")
        print("systemnnn_spt e|export [--encoding sjis] [-o outpath] inpath")
        print("systemnnn_spt i|import [--encoding gbk] [-o outpath] [-t|--txtpath] inpath")
        return
    
    parser = argparse.ArgumentParser()
    parser.add_argument('method', help="p|print, e|export, i|import")
    parser.add_argument('inpath')
    parser.add_argument('--encoding', default=None, help="sjis|gbk")
    parser.add_argument('-t', '--txtpath', default=None, help="the ftextpath to import text")
    parser.add_argument('-o', '--outpath', default=None)
    if cmdstr:  args = parser.parse_args(cmdstr.split(" "))
    else: args = parser.parse_args()

    inpath = args.inpath
    outpath = args.outpath
    if args.method in ('p', 'print'):
        encoding = args.encoding if args.encoding else 'sjis'
        print_spt(inpath, encoding)
    elif args.method in ('e', 'export'):
        encoding = args.encoding if args.encoding else 'sjis'
        if not outpath: outpath = "out.txt"
        export_spt(inpath, outpath, encoding)
    elif args.method in ('i', 'import'):
        encoding = args.encoding if args.encoding else 'gbk'
        txtpath = args.txtpath
        if not txtpath: txtpath = inpath + ".txt"
        if not outpath: outpath = "out.spt"
        import_spt(inpath, txtpath, outpath, encoding)
    else: raise ValueError(f"method {args.method} not valid!")

if __name__ == '__main__':
    # debug()
    main()
    pass

"""
history:
v0.1, initial version for 倭人異聞録～あさき、ゆめみし～
"""