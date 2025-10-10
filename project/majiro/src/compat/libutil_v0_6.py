# -*- coding: utf-8 -*-
__version__  = "0.6"
__description__ = f"""
util functions and structures for galgame localization
    v{__version__}, developed by devseed
"""

import os
import gzip
import zipfile
from io import BytesIO
from datetime import datetime
from dataclasses import dataclass
from typing import Union, List, Tuple

try: # optional libraries to import
    import numpy as np
    from PIL import Image
except ImportError: pass

# util functions
def readlines(data: bytes, encoding='utf-8', encoding_error='ignore', keepends=True) -> List[str]:
    return str.splitlines(str(data, encoding, encoding_error), keepends=keepends)

def readlines_deprecated(data: bytes, encoding='utf-8', encoding_error='ignore') -> List[str]:
    i = 0
    start = 0
    lines = []
    mem = memoryview(data)
    while i < len(mem): 
        if mem[i] == ord('\r'):
            if i+1 < len(mem) and mem[i+1] == '\n': i += 1
            lines.append(str(mem[start: i+1], encoding, encoding_error))
            start = i+1
        elif mem[i] == ord('\n'):
            lines.append(str(mem[start: i+1], encoding, encoding_error))
            start = i+1
        i += 1
    if start < len(mem): lines.append(str(mem[start:], encoding, encoding_error))
    return lines

def writelines(lines: List[str], encoding='utf-8', encoding_error='ignore') -> bytes:
    bufio = BytesIO()
    for line in lines: 
        bufio.write(line.encode(encoding, encoding_error))
    data = bufio.getvalue()
    bufio.close()
    return data

def readbytes(inobj: Union[str, BytesIO]) -> bytes:
    def load_gz(path) -> bytes: # path/x.gz 
        with gzip.GzipFile(path, 'rb') as fp: 
            return fp.read()
        
    def load_zip(path) -> bytes: # path1/x.zip>path2/y
        path1, path2 = path.split(".zip>")
        path2 = path2.replace('\\', '/')
        with zipfile.ZipFile(path1 + ".zip", 'r') as fp1:
            with fp1.open(path2, 'r') as fp2:
                return fp2.read()
    
    def load_direct(path) -> bytes:
        with open(path, 'rb') as fp:
            return fp.read()
        
    if type(inobj)==str:
        path = inobj
        if os.path.splitext(path)[1] == '.gz': data = load_gz(path)
        elif ".zip>" in path: data = load_zip(path)
        else: data = load_direct(path)
    else:
        data = inobj.read()
    return data

def writebytes(outobj: Union[str, BytesIO], dataobj: Union[bytes, BytesIO]) -> int:
    def save_gz(path, data) -> int: # path/x.gz 
        with gzip.GzipFile(path, 'wb') as fp: 
            return fp.write(data)
        
    def save_zip(path, data) -> int: # path1/x.zip>path2/y
        path1, path2 = path.split(".zip>")
        path2 = path2.replace('\\', '/')
        with zipfile.ZipFile(path1 + ".zip", 'a') as fp1:
            now = datetime.now()
            info = zipfile.ZipInfo(filename=path2, date_time= \
                    (now.year, now.month, now.day, now.hour, now.minute, now.second))
            fp1.writestr(info, data)
            return len(data)
    
    def save_direct(path, data) -> int:
        with open(path, 'wb') as fp:
            return fp.write(data)
        
    if type(dataobj) in {bytes, bytearray, memoryview}: data = dataobj
    else: data = dataobj.read() 
    
    size = 0
    if type(outobj)==str:
        path = outobj
        if os.path.splitext(outobj)[1]==".gz": size = save_gz(path, data)
        elif ".zip>" in outobj: size = save_zip(path, data)
        else: size = save_direct(path, data)
    else: size = outobj.write(data)
    return size

def readimage(inobj: Union[bytes, str], pixel_format=None, img_format=None, palette=None):
    """
    read image from bytes, bytearray, io or file
    :param pixel_format: "L", "RGBA", "P", "PA"
    :param img_format:  "png", "jpeg" see support by python3 -m PIL
    :param palette: output palette
    :return: numpy array of image
    """

    bufio = BytesIO(readbytes(inobj)) 
    fmt = None if img_format is None else [img_format]
    pil = Image.open(bufio, "r", fmt)
    pil.readonly = False
    if palette is not None: 
        pil.apply_transparency() # add transparency to alpha
        pil_palette = pil.getpalette("RGBA")
        if pil_palette: palette.reshape((-1))[:len(pil_palette)] = pil_palette
    if pixel_format is not None: pil = pil.convert(pixel_format)
    img = np.asarray(pil)
    bufio.close()
    return img

def writeimage(outobj: Union[str, BytesIO], img, pixel_format=None, img_format="png", palette=None):
    """
    write image to io or file
    :param pixel_format: "L", "RGBA", "P", "PA"
    :param img_format:  "png", "jpeg" see support by python3 -m PIL
    :param palette: output palette
    :return: size of image
    """

    bufio = BytesIO()
    pil = Image.fromarray(img)
    pil.readonly = False
    if palette is not None: pil.putpalette(palette.reshape(-1), "RGBA")
    if pixel_format is not None: pil = pil.convert(pixel_format, palette=pil.palette)
    pil.save(bufio, img_format)
    data = bufio.getvalue()
    bufio.close()
    return writebytes(outobj, data)

def filter_loadfiles(targets: Union[int, str, List]=None):
    """
    :params targets: can be 0, 'k', [0], [(0, 'utf8', 'ignore', False), 'k'], 
    """
    
    if targets == None: targets = [0]
    if type(targets) != list:  targets = [targets]
    
    def wrapper1(func): # decorator(dec_args)(func)(fun_args)
        def wrapper2(*_args, **kw):
            args = list(_args)
            for i, t in enumerate(targets):
                w = None # for args or kw
                t0 = t[0] if type(t)==tuple else t # for index
                t1 = t[1:] if type(t)==tuple else None # for encoding, encoding_error
                if type(t0)==int and type(args[t0])==str: w=args
                elif type(t0)==str and t in kw and type(kw[t0]) == str: w=kw
                if w is None: continue # no target arg
                data = readbytes(w[t0])
                w[t0] = readlines(data, *t1) if t1 else data
            return func(*args, **kw)
        return wrapper2
    return wrapper1

def filter_loadimages(targets: Union[int, str, List]=None):
    """
    :params targets: can be 0, 'k', [0], [(0, 'RGBA', 'png', palette), 'k'], 
    """
    
    if targets == None: targets = [0]
    if type(targets) != list:  targets = [targets]
    
    def wrapper1(func): # decorator(dec_args)(func)(fun_args)
        def wrapper2(*_args, **kw):
            args = list(_args)
            for i, t in enumerate(targets):
                w = None # for args or kw
                t0 = t[0] if type(t)==tuple else t # for index
                t1 = t[1:] if type(t)==tuple else None # for encoding, encoding_error
                if type(t0)==int and type(args[t0])==str: w=args
                elif type(t0)==str and t in kw and type(kw[t0]) == str: w=kw
                if w is None: continue # no target arg
                w[t0] = readimage(w[t0], *t1)
            return func(*args, **kw)
        return wrapper2
    return wrapper1

# structures
@dataclass
class ftext_t:
    addr: int = 0
    size: int = 0
    text: str = ""

@dataclass
class tbl_t:
    tcode : bytes = b""
    tchar : str = ""

@dataclass
class jtable_t: # jump table
    addr: int = 0
    addr_new: int = 0
    toaddr: int = 0
    toaddr_new: int = 0

@dataclass
class tile_t:
    w: int
    h: int
    bpp: int = 0
    size: int = 0

@dataclass
class msg_t:
    id: int = 0
    msg: str = ""
    type: int = 0

# check function
def valid_tile(info: tile_t, shape=None):
    if shape:
        if info.h <= 0: info.h = shape[0]
        if info.w <= 0: info.w = shape[1]
        if info.bpp == 0: info.bpp = 8 if len(shape) <3 else shape[2]*8
    else:
        if info.h <=0: info.h = info.w
    if info.size <=0: info.size = int((info.h * info.w * info.bpp + 7)// 8)

# serilization functions
def load_batch(strobj: str, *, encoding="utf-8", no_process=False) -> List[str]:
    """
    load the batch paths from a file or str
    in format dir;path1;...
    """

    if strobj.find(";") < 0: lines = readlines(readbytes(strobj), encoding, keepends=False)
    else: lines = strobj.split(";")
    if no_process is False: # apply the first as path and removes empty
        dirpath = lines[0]
        lines = [os.path.join(dirpath, line) for line in lines[1:] \
                 if len(line) > 0 and lines[0]!="#"]
    return lines

def save_ftext(ftexts1: List[ftext_t], ftexts2: List[ftext_t], 
        outpath: str = None, *, encoding="utf-8", width_index = (5, 6, 3)) -> List[str]:
    """
    format text, such as ●num|addr|size● text
    :param ftexts1[]: text dict array in '○' line, 
    :param ftexts2[]: text dict array in '●' line
    :return: ftext lines
    """

    width_num, width_addr, width_size = width_index
    if width_num==0: width_num = len(str(len(ftexts1)))
    if width_addr==0: width_addr = len(hex(max(t.addr for t in ftexts1))) - 2
    if width_size==0: width_size = len(hex(max(t.size for t in ftexts1))) - 2

    lines = []
    fstr1 = "○{num:0%dd}|{addr:0%dX}|{size:0%dX}○ {text}\n" \
            % (width_num, width_addr, width_size)
    fstr2 = fstr1.replace('○', '●')
    if not ftexts1: ftexts1 = [None] * len(ftexts2)
    if not ftexts2: ftexts2 = [None] * len(ftexts1)
    for i, (t1, t2) in enumerate(zip(ftexts1, ftexts2)):
        if t1: lines.append(fstr1.format(num=i, addr=t1.addr, size=t1.size, text=t1.text))
        if t2: lines.append(fstr2.format(num=i, addr=t2.addr, size=t2.size, text=t2.text))
        lines.append("\n")

    if outpath: writebytes(outpath, writelines(lines, encoding))

    return lines 

@filter_loadfiles(0)
def load_ftext(inobj: Union[str, List[str], Tuple], *, 
        encoding="utf-8") -> Tuple[List[ftext_t], List[ftext_t]]:
    """
    format text, such as ●num|addr|size● text
    :param inobj: can be path, or lines[], in the end, no \r \n
    :return: ftexts1[]: text dict array in '○' line, 
             ftexts2[]: text dict array in '●' line
    """

    if inobj==None: return None
    if type(inobj) == tuple: return inobj
    ftexts1, ftexts2 = [], []
    lines = readlines(inobj, encoding, "ignore", False) if type(inobj) != list else inobj
    if len(lines) > 0: lines[0] = lines[0].lstrip("\ufeff") # remove bom
    for line in lines:
        if len(line) <= 0: continue
        indicator = line[0]
        if indicator == "#": continue
        if indicator not in {"○", "●"}: continue
        _, t1, *t2 = line.split(indicator)
        t2 = "".join(t2)
        ftext = ftext_t(-1, 0, t2[1:])
        try: 
            _, t12, t13 = t1.split('|')
            ftext.addr, ftext.size = int(t12, 16), int(t13, 16)
        except ValueError: pass 
        if indicator=='○': ftexts1.append(ftext)
        else: ftexts2.append(ftext)

    return ftexts1, ftexts2

def save_tbl(tbl: List[tbl_t], outpath=None, *, encoding='utf-8')  -> List[str]:
    lines = []
    for t in tbl:
        raw_str = ""
        for d in t.tcode: raw_str += f"{d:02X}"
        line = ("{:s}={:s}\n".format(raw_str, t.tchar))
        lines.append(line)
    if outpath: writebytes(outpath, writelines(lines, encoding))
    return lines

@filter_loadfiles(0)
def load_tbl(inobj: Union[str, List[str], List[ftext_t]], *, encoding='utf-8') ->  List[tbl_t]:
    """
    tbl file format "tcode=tchar", 
    :param inobj: can be path, or lines[], in the end, no \r \n
    :return: [(charcode, charstr)]
    """

    if inobj==None: return None
    if len(inobj) > 0 and hasattr(inobj[0], "tchar"): return inobj
    tbl: List[tbl_t] = []
    lines = readlines(inobj, encoding, 'ignore', False) if type(inobj) != list else inobj
    for line in lines:
        if len(line) <= 0: continue
        indicator = line[0]
        if indicator == "#": continue
        if line.find("==") == -1: t1, tchar = line.split('=')
        else: t1 = line.split('=')[0]; tchar = '='
        tcode = bytearray(len(t1)//2)
        for i in range(len(t1)//2): tcode[i] = int(t1[2*i: 2*i+2], 16)
        tbl.append(tbl_t(bytes(tcode), tchar))

    return tbl