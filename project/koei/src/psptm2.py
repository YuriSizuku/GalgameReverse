"""
  for decoding and encoding tm2 format texture
    v0.3.1, developed by devseed

    tested games:
    ULJM05054 金色のコルダ (index4)
    ULJM06326 Jewelic Nightmare (index8)


    refer:
    https://openkh.dev/common/tm2.html
    https://github.com/marco-calautti/Rainbow
    
"""

import os
import sys
import numpy as np
from enum import Enum
from ctypes import *
from PIL import Image, ImagePalette
from typing import Tuple, List

class COLOR_TYPE(Enum):
    UNDEFINED = 0
    A1B5G5R5 = 1
    X8B8G8R8 = 2
    A8B8G8R8 = 3
    INDEX4 = 4
    INDEX8 = 5

class tm2pic_t(Structure):
    _fields_ = [
        ('size_total', c_uint32), # size stored in file
        ('size_palette', c_uint32),  # clut size palette, palette is at the end
        ('size_image', c_uint32), # bitmap size
        ('size_header', c_ushort),
        ('count_color', c_ushort), # used by clut
        ('format', c_ubyte),
        ('count_mipmap', c_ubyte),
        ('type_clutcolor', c_ubyte),
        ('type_imagecolor', c_ubyte), # IMAGE_COLOR_TYPE
        ('width', c_ushort),
        ('height', c_ushort),
        ('reg_gstex', c_uint64 * 2),
        ('reg_gsflag', c_uint32),
        ('reg_gsclut', c_uint32),
        ('picdata', c_byte * 1)
    ]

class tm2_t(Structure):
    _fields_ = [
        ('magic', c_char * 4), # TIM2
        ('version', c_ubyte),  # 4
        ('format', c_ubyte),   # 0
        ('count', c_ushort),
        ('reserved', c_int * 2),
        ('pictures', tm2pic_t * 1)
    ]

class Tm2():
    @classmethod
    def swizzle(cls, x, y, w, tilew=32, tileh=8) -> Tuple[int, int]:
        """
        tilew 32 for 4bpp, 16 for higher than 8bpp
        0 1 2 3     0 1 4 5 
        4 5 6 7  -> 2 3 6 7
        """

        idx = x + w*y
        tilesize = tilew * tileh
        tileline = w // tilew
        tileidx = idx // tilesize
        tiley = tileidx // tileline
        tilex = tileidx % tileline

        tileinneridx = idx % tilesize
        tileinnery = tileinneridx // tilew
        tileinnerx = tileinneridx % tilew

        x2 = tilex * tilew + tileinnerx
        y2 = tiley * tileh + tileinnery
        return (x2, y2)
    
    @classmethod
    def deinterlace_palatte(cls, palatte):
        """
        https://github.com/marco-calautti/Rainbow/blob/51bb1834181c474893bdfbd810e3a45fe6397914/Rainbow.ImgLib/ImgLib/Filters/TIM2PaletteFilter.cs#L26
        """

        parts = len(palatte) // 32
        stripes = 2
        colors = 8
        blocks = 2
        
        newpallate = [0] * len(palatte)
        i = 0
        for part in range(parts):
            for block in range(blocks):
                for stripe in range(stripes):
                    for color in range(colors):
                        i2 = part * colors * stripes * blocks + block * colors + stripe * stripes * colors + color 
                        newpallate[i] = palatte[i2]
                        i+=1
        assert(i==len(palatte))
        return newpallate
    
    @classmethod
    def interlace_palatte(cls, palatte):
        """
        https://github.com/marco-calautti/Rainbow/blob/51bb1834181c474893bdfbd810e3a45fe6397914/Rainbow.ImgLib/ImgLib/Filters/TIM2PaletteFilter.cs#L26
        """

        parts = len(palatte) // 32
        stripes = 2
        colors = 8
        blocks = 2
        
        newpallate = [0] * len(palatte)
        i = 0
        for part in range(parts):
            for block in range(blocks):
                for stripe in range(stripes):
                    for color in range(colors):
                        i2 = part * colors * stripes * blocks + block * colors + stripe * stripes * colors + color 
                        newpallate[i2] = palatte[i]
                        i+=1
        assert(i==len(palatte))
        return newpallate
    
    @classmethod
    def idx2xy(cls, idx, w) -> Tuple[int, int]:
        return (idx%w, idx//w)
    
    @classmethod
    def xy2idx(cls, x, y, w) -> int:
        return x + y*w

    @classmethod
    def deswizzle_img(cls, imgin: np.ndarray, tilew=32, tileh=8) -> np.ndarray:
        """
        deswizzle in image level
        img h, w must be devided by tilew, tileh
        """
        
        imgout = np.zeros_like(imgin)
        (h, w) = imgout.shape[:2]
        for y in range(h):
            for x in range(w):
                (x2, y2) = cls.swizzle(x, y, w, tilew, tileh)
                imgout[y2, x2] = imgin[y, x]
        return imgout

    @classmethod
    def swizzle_img(cls, imgin: np.ndarray, tilew=32, tileh=8) -> np.ndarray:
        """
        swizzle in image level
        img h, w must be devided by tilew, tileh
        """
                
        imgout = np.zeros_like(imgin)
        (h, w) = imgin.shape[:2]
        for y in range(h):
            for x in range(w):
                (x2, y2) = cls.swizzle(x, y, w, tilew, tileh)
                imgout[y, x] = imgin[y2, x2]
        return imgout

    def __init__(self, data=None) -> None:
        if data: self.parse(data)

    def parse(self, data: bytearray):
        self.m_data = data
        self.tm2 = tm2_t.from_buffer(data)
        if self.tm2.magic != b'TIM2':
            raise ValueError(f"unknow magic {self.tm2.magic}")
        
        offset = addressof(self.tm2.pictures) - addressof(self.tm2)
        self.tm2pics = [tm2pic_t.from_buffer(data, offset)]
        for _ in range(self.tm2.count-1):
            offset += self.tm2pics[-1].size_total
            self.tm2pics.append(tm2pic_t.from_buffer(data, offset))

    def get_picdata_offset(self, pic):
        return addressof(pic) + pic.size_header - addressof(self.tm2) 

    def decode_img(self, pic: tm2pic_t) -> Tuple[np.ndarray, List[np.ndarray]]:
        """
        decode single image from tm2 data
        """

        palette = None
        w, h = pic.width, pic.height
        offset_picdata = self.get_picdata_offset(pic)
        color_type = COLOR_TYPE(pic.type_imagecolor)
        interlaced = pic.type_clutcolor & 0x80 == 0 
        if color_type == COLOR_TYPE.INDEX4 or \
            color_type == COLOR_TYPE.INDEX8 :
            size_palette = pic.size_palette # load palette
            offset_palette = offset_picdata + pic.size_image # palette is at the end
            palette = [np.frombuffer(self.m_data, np.uint8, 4, cur) 
                    for cur in range(offset_palette, offset_palette + size_palette, 4)]
            if interlaced:  palette = self.deinterlace_palatte(palette)

            img = np.zeros((h, w, 4), dtype=np.uint8) # load image
            for y in range(h):
                for x in range(w):
                    pos = x + w*y
                    if color_type == COLOR_TYPE.INDEX4:
                        d = self.m_data[offset_picdata + pos//2]
                        d = d & 0xf if pos%2==0 else (d >> 4) & 0xf
                    elif color_type == COLOR_TYPE.INDEX8:
                        d = self.m_data[offset_picdata + pos]
                    img[y, x] = palette[d]
        elif color_type == COLOR_TYPE.A8B8G8R8:
            img = np.frombuffer(self.m_data, 
                    dtype=np.uint8, cout=pic.size_image, 
                    offset=offset_picdata).resize((h, w, 4))
        else: raise NotImplementedError(f"not support image color type {color_type}")

        return img, palette

    def encode_img(self, pic: tm2pic_t, img: np.ndarray, palette: List[np.ndarray]) -> tm2pic_t:
        """
        encode single image to tm2 data
        """

        h, w = img.shape[:2]
        color_type = COLOR_TYPE(pic.type_imagecolor)
        ppicdata = cast(c_void_p(addressof(pic.picdata)), POINTER(c_ubyte))
        if color_type == COLOR_TYPE.INDEX4 or \
            color_type == COLOR_TYPE.INDEX8:
            palettedata = np.array(palette).tobytes()
            assert(len(palettedata) == pic.size_palette)
            ppalette = c_void_p(addressof(pic.picdata) + pic.size_image)
            if color_type == COLOR_TYPE.INDEX4:
                assert(img.size == 2*pic.size_image)
                for i in range(pic.size_image):
                    low, high = img[2*i//w, 2*i%w], img[(2*i+1)//w, (2*i+1)%w]
                    ppicdata[i] = (low&0xf) + ((high<<4)&0xf0)
            elif color_type == COLOR_TYPE.INDEX8:
                interlaced = pic.type_clutcolor & 0x80 == 0
                if interlaced: palettedata = np.array(self.interlace_palatte(palette)).tobytes()
                assert(img.size == pic.size_image)
                memmove(ppicdata, img.tobytes(), pic.size_image)
            memmove(ppalette, palettedata, pic.size_palette)
        elif color_type == COLOR_TYPE.A8B8G8R8:
            assert(img.size == pic.size_image)
            memmove(ppicdata, img.tobytes(), pic.size_image)
        else: raise NotImplementedError(f"not support image color type {color_type}")

    def extract(self, idx, outpath="out.png", use_swizzle=False):
        if idx > self.tm2.count or idx < 0: return None
        pic = self.tm2pics[idx]
        if(pic.count_mipmap > 1): raise NotImplementedError(f"not support mipmap {pic.count_mipmap}")
        
        img, palette = self.decode_img(pic)
        if use_swizzle:
            tilew, tileh = 16, 8
            if len(palette)==16: tilew=32
            img = self.deswizzle_img(img, tilew, tileh)

        if outpath != "":
            imgpil = Image.fromarray(np.array(img)) 
            if palette and 0: # not extract with palatte, this makes alpha not work
                palettepil = ImagePalette.ImagePalette("RGBA", np.array(palette).tobytes())
                imgpil = imgpil.convert("P", palette=palettepil, colors=len(palette)//2)
            imgpil.save(outpath)  
        return img

    def insert(self, idx, inpath="", use_swizzle=False):
        if idx > self.tm2.count or idx < 0: return None
        pic = self.tm2pics[idx]
        if(pic.count_mipmap > 1): raise NotImplementedError(f"not support mipmap {pic.count_mipmap}")
        
        palette = None
        imgpil = Image.open(inpath)
        if pic.type_imagecolor == COLOR_TYPE.INDEX4.value:
            imgpil = imgpil.convert("P", colors=16)
            palette = [np.array(color, np.uint8) for color in imgpil.palette.colors]
            if len(palette) < 16: palette.extend([np.array([0, 0, 0, 0], dtype=np.uint8)]*(16- len(palette)))
        elif pic.type_imagecolor == COLOR_TYPE.INDEX8.value:
            imgpil = imgpil.convert("P", colors=256)
            palette = [np.array(color, np.uint8) for color in imgpil.palette.colors]
            if len(palette) < 256: palette.extend([np.array([0, 0, 0, 0], dtype=np.uint8)]*(256- len(palette)))
        img = np.array(imgpil)
 
        if use_swizzle:
            tilew, tileh = 16, 8
            if len(palette)==16: tilew=32
            img = self.swizzle_img(img, tilew, tileh)
        
        self.encode_img(pic, img, palette)
        self.parse(self.m_data) 

def extract_tm2(tm2path, outdir="out", use_swizzle=False):
    with open(tm2path, 'rb') as fp:
        data = bytearray(fp.read())
    tm2 = Tm2(data)
    for i in range(tm2.tm2.count):
        name = os.path.basename(os.path.splitext(tm2path)[0])
        path = os.path.join(outdir, f"{name}_{i}.png")
        tm2.extract(i, path, use_swizzle)
        print(f"{i+1}/{tm2.tm2.count}: {path} extracted")

def insert_tm2(tm2path, indir, outpath="out.tm2", use_swizzle=False):
    with open(tm2path, 'rb') as fp:
        data = bytearray(fp.read())
    tm2 = Tm2(data)
    for i in range(tm2.tm2.count):
        name = os.path.basename(os.path.splitext(tm2path)[0])
        path = os.path.join(indir, f"{name}_{i}.png")
        if os.path.exists(path):
            tm2.insert(i, path, use_swizzle)
            print(f"{i+1}/{tm2.tm2.count}: {outpath} inserted")
    with open(outpath, 'wb') as fp:
        fp.write(data)

def debug():
    pass

def cli(argv):
    def cmd_help():
        print("psptm2 tools v0.3, developed by devseed")
        print("usage")
        print("psptm2 e[swi] tm2path [outdir] # convert tm2 to pngs")
        print("psptm2 i[swi] tm2path indir [outpath] # insert pngs to tm2")
        print("psptm2 c[swi|deswi][tilew|tileh] imgpath [outpath] # swizzle or deswizzle image")
        print("examples: ")
        print("psptm2 eswi xxx.tm2 ./")
        print("psptm2 iswi xxx.tm2 ./ xxx_rebuild.tm2")
        print("psptm2 cdeswi1608 xxx.png xxx_deswi.png")

    def cmd_export():
        outdir = argv[3] if len(argv) > 3 else "out"
        extract_tm2(inpath, outdir, use_swizzle)
    
    def cmd_import():
        indir = argv[3]
        outpath = argv[4] if len(argv) > 4 else "out.tm2"
        insert_tm2(inpath, indir, outpath, use_swizzle)

    def cmd_convert():
        outpath = argv[3] if len(argv) > 3 else "out.png"
        imgpil = Image.open(inpath)
        tilew, tileh = 16, 8
        if cmdtype[1:4] == 'swi':
            if len(cmdtype) > 4: tilew = int(cmdtype[4:6], 10)
            if len(cmdtype) > 6: tileh = int(cmdtype[6:8], 10)
            img = Tm2.swizzle_img(np.array(imgpil), tilew, tileh)
        elif cmdtype[1:6] == 'deswi':
            if len(cmdtype) > 6: tilew = int(cmdtype[6:8], 10)
            if len(cmdtype) > 8: tileh = int(cmdtype[8:10], 10)
            img = Tm2.deswizzle_img(np.array(imgpil), tilew, tileh)
        else: raise NotImplementedError(f"unknow type {cmdtype}")
        imgpil2 = Image.fromarray(img, mode=imgpil.mode)
        if imgpil.mode=='P': imgpil2.putpalette(imgpil.palette)
        imgpil2.save(outpath)

    if len(argv) < 3: cmd_help();return
    cmdtype = argv[1].lower()
    inpath = argv[2] 
    use_swizzle  = True if cmdtype.find("swi") > 0 else False
    if cmdtype[0] == 'e': cmd_export()
    elif cmdtype[0] == 'i': cmd_import()
    elif cmdtype[0] == 'c': cmd_convert()
    else: raise NotImplementedError(f"unknow type {cmdtype}")

if __name__=='__main__':
    # debug()
    cli(sys.argv)

"""
history:
  v0.1, implement export iamge with COLOR_A8B8G8R8, COLOR_INDEX4, COLOR_INDEX8
  v0.2, add swizzle deswizzle method
  v0.3, add insert png32 to tim2, and convert with index4/index8 if necessory
  v0.3.1, support index8 interlaced pallatte format 
"""