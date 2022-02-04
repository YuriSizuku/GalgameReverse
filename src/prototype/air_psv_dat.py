""" 
    prototype dat picture decode encode tool
    for extracting and importimg images in psv air
    v0.6, developed by devseed
    
    inspired by 
    https://github.com/wetor/LucaSystemTools/blob/master/LucaSystemTools/LucaSystemTools/DatParser.cs
    Thanks for @wector and @deqxj00
    
    v0.1 dat, rgba, rga normal picture with magic 0x02012000, tested in psv air
    v0.3 added block delta encoding with 02 type
    v0.4 added panel type, magic 0x2012804
    v0.5 encoding picture (inject normal png to dat), but crash in game
    v0.6 fixed the encoding header building
"""

import os
import struct
import cv2
import numpy as np
import math
from io import BytesIO

def read_dat_heaader(fp):
    dat_header = dict()
    dat_header['magic'] = int.from_bytes(fp.read(4), 'big', signed=False)
    dat_header['width'] = int.from_bytes(fp.read(2), 'little', signed=False)
    dat_header['height'] = int.from_bytes(fp.read(2), 'little', signed=False)
    dat_header['dict_num'] = int.from_bytes(fp.read(2), 'little', signed=False) #01 01 257
    dat_header['colorbit_type'] = int.from_bytes(fp.read(1), 'little', signed=False)
    dat_header['colorbit_type2'] = int.from_bytes(fp.read(1), 'little', signed=False) # delta encoding
    dat_header['unknow2'] = int.from_bytes(fp.read(4), 'little', signed=False)
    dat_header['width2'] = int.from_bytes(fp.read(2), 'little', signed=False)
    dat_header['height2'] = int.from_bytes(fp.read(2), 'little', signed=False)
    dat_header['unknow3'] = int.from_bytes(fp.read(4), 'little', signed=False)
    dat_header['width3'] = int.from_bytes(fp.read(2), 'little', signed=False)
    dat_header['height3'] = int.from_bytes(fp.read(2), 'little', signed=False)
    dat_header['unknow4'] = int.from_bytes(fp.read(4), 'little', signed=False)
    dat_header['unknow5'] = int.from_bytes(fp.read(4), 'little', signed=False)
    dat_header['unknow6'] = int.from_bytes(fp.read(4), 'little', signed=False)
    dat_header['unknow7'] = int.from_bytes(fp.read(4), 'little', signed=False) #compressed size  + header_size(0x3c)
    dat_header['width4'] = int.from_bytes(fp.read(2), 'little', signed=False)
    dat_header['height4'] = int.from_bytes(fp.read(2), 'little', signed=False)
    dat_header['unknow8'] = int.from_bytes(fp.read(2), 'little', signed=False) #block_count*8+8+4
    dat_header['block_count'] = int.from_bytes(fp.read(2), 'little', signed=False)
    dat_header['decompressed_len'] = int.from_bytes(fp.read(4), 'little', signed=False)
    dat_header['compressed_len'] = int.from_bytes(fp.read(4), 'little', signed=False)
    return dat_header

def lzw_decompress(data):
    lzw_dict = dict()
    decompressed = BytesIO()
    for i in range(256+1):  # very strange with 257 default value in dictionay
        lzw_dict[i] = int.to_bytes(i%256, 1, 'little', signed=False)

    w = lzw_dict[int.from_bytes(data[0:2], 'little', signed=False)]
    decompressed.write(w)    
    for i in range(2, len(data), 2):
        k = int.from_bytes(data[i:i+2], 'little', signed=False)
        entry = None # entry suffix word
        if k in lzw_dict:
            entry = lzw_dict[k]
        elif k == len(lzw_dict):
            entry = w + w[0:1]
        decompressed.write(entry)
        lzw_dict[len(lzw_dict)] =  w + entry[0:1] # new sequence; add it to the dictionary
        w = entry # w prefix word

    return decompressed.getbuffer()

def lzw_compress(data):
    lzwc_dict = dict() # lzw compress dict
    compressed = BytesIO()
    for i in range(256+1): 
        if i<256:
            lzwc_dict[int.to_bytes(i,  1, 'little')] = int.to_bytes(len(lzwc_dict), 2, 'little') 
        else:
            lzwc_dict[int.to_bytes(0x3943731902385265,  8, 'little')] = int.to_bytes(len(lzwc_dict), 2, 'little') # this is strange so that do not use this value
    pw = data[0:1] # prefix word
    for i in range(1, len(data)):
        c = data[i:i+1] # current char
        s  = pw + c
        if s in lzwc_dict:
            pw = s
        else:
            # print(i, s, len(lzwc_dict), lzwc_dict[pw])
            lzwc_dict[s] = int.to_bytes(len(lzwc_dict), 2, 'little')
            compressed.write(lzwc_dict[pw])
            pw = c
    # print(len(lzwc_dict))
    compressed.write(lzwc_dict[pw]) # don't forget the last char 
    return compressed.getbuffer()

def decode_dat(inpath, outpath="out.png"):
    with open(inpath, 'rb') as fp:
        # read header
        dat_header = read_dat_heaader(fp)
        color_panel = None
        if dat_header['magic'] == 0x02012000: 
            print("no colorpanel type")
        elif dat_header['magic'] == 0x2012804:
            color_panel = np.zeros([256, 4], dtype=np.uint8)
            print("colorpanel type")
        else:
            print("Unsopported file type "+str(hex(dat_header['magic'])))
            return None

        # init value
        height = dat_header['height']
        width = dat_header['width']
        block_count = dat_header['block_count']
        colorbit_type1 = dat_header['colorbit_type'] 
        colorbit_type2 = dat_header['colorbit_type2'] 
        if colorbit_type1 == 0x80:
            color_channel = 4
        elif colorbit_type1 == 0xa8:
            color_channel = 3
        elif colorbit_type1 == 0x81:
            color_channel = 1 
        print("%s loaded, %dx%d, block %d, magic=0x%x, %02x %02x"%(inpath, width, height, block_count, dat_header['magic'], colorbit_type1, colorbit_type2))
        
        # if has color panel
        if color_panel is not None:
            fp.seek(0x28)
            print("color panel start at "+str(hex(fp.tell())))
            for i in range(color_panel.shape[0]):
                r,g, b,a = struct.unpack("<BBBB", fp.read(4))
                color_panel[i] = np.array([b,g,r,a])
            fp.seek(18, 1)
            block_count = int.from_bytes(fp.read(2), 'little')
            dat_header['decompressed_len'] =  int.from_bytes(fp.read(4), 'little')
            dat_header['compressed_len'] =  int.from_bytes(fp.read(4), 'little')
            print("color end start at "+str(hex(fp.tell())))

        # read size index
        arr_rawsize = []
        arr_cpsize = [] # compressed size
        for idx in range(block_count): 
            cpsize, rawsize  = struct.unpack("<II", fp.read(8))
            arr_rawsize.append(rawsize)
            arr_cpsize.append(cpsize)

        # uncompress block
        raw_stream = BytesIO()
        for idx in range(block_count): 
            cpsize = arr_cpsize[idx]
            addr = fp.tell()
            data_raw = lzw_decompress(fp.read(cpsize))

            if colorbit_type2 == 0x02: # delta encoding in each block
                px_num = len(data_raw) / color_channel
                linebytes_num = width * color_channel
                preline = bytearray(data_raw[0:linebytes_num])
                for h in range(1, math.ceil(px_num/width)):
                    if (h+1) * linebytes_num < len(data_raw):
                        length = linebytes_num
                    else: length = len(data_raw) % linebytes_num
                    curline = bytearray(data_raw[h*linebytes_num: h*linebytes_num+length])
                    for i in range(length):
                        curline[i] = (curline[i] + preline[i] - 1) % 256
                    data_raw[h*linebytes_num: h*linebytes_num+length] = curline
                    preline = curline
            raw_stream.write(data_raw)
            print("lzw block %d, at 0x%x, cpsize=%d, dcpsize=%d rawsize=%d"%(idx, addr, cpsize, len(data_raw), arr_rawsize[idx]))
        
        print("picture data size "+str(len(raw_stream.getvalue()))+", type "+str(hex((colorbit_type2<<8)+colorbit_type1)))

        # make picture        
        raw_stream.seek(0)
        if color_panel is not None:
            img = np.zeros([height, width, 4], dtype=np.uint8)
        else: img = np.zeros([height, width, color_channel], dtype=np.uint8)
        for y in range(height):
            for x in range(width):
                if  color_channel==4 : # RGBA8888
                    r, g, b, a = struct.unpack("<BBBB", raw_stream.read(4))
                    px = np.array([b, g, r, a], dtype=np.uint8)
                elif color_channel==3 : # RGB888
                    r, g, b = struct.unpack("<BBB", raw_stream.read(3))
                    px = np.array([b, g, r], dtype=np.uint8)
                elif color_channel==1: # color panel
                    d = struct.unpack('<B', raw_stream.read(1))[0]
                    px = color_panel[(d-1) % 256] + 1 # do not use px+=px, this changed color panel
                img[y][x] = px - 1
        cv2.imwrite(outpath, img)

def encode_dat(inpath, datpath, outpath = "out.dat"):
    with open(datpath, 'rb') as fp:
        # read the datpath header to be injected
        magic = int.from_bytes(fp.read(4), 'big')
        color_panel = None
        if magic == 0x02012000: 
            print("no colorpanel type")
        elif magic == 0x2012804:
            color_panel = np.zeros([256, 4], dtype=np.uint8)
            print("colorpanel type")
        else:
            print("Unsopported file type "+str(hex(magic)))
            return None

        # read header of datpath to be injected
        img = cv2.imread(inpath, cv2.IMREAD_UNCHANGED)
        height, width, color_channel = img.shape
        if color_channel == 4:
            colorbit_type1 = 0x80
        elif color_channel == 3:
            colorbit_type1 = 0xa8
        elif color_channel == 1 :
           colorbit_type1 = 0x81
        
        fp.seek(0)
        if color_panel is not None:
            fp.seek(0x28)
            print("color panel start at "+str(hex(fp.tell())))
            for i in range(color_panel.shape[0]):
                r,g, b,a = struct.unpack("<BBBB", fp.read(4))
                color_panel[i] = np.array([b,g,r,a])
            fp.seek(28, 1)
            header_end = fp.tell()
            print("header end start at "+str(hex(header_end)))
            fp.seek(0)
            header_data = bytearray(fp.read(header_end))
            
        else: 
            header_data = bytearray(fp.read(0x3c))
 
        block_count = int.from_bytes(header_data[-10:-8], 'little')  
        block_count += 4 # avoid dict overflow
        header_data[-10:-8] = int.to_bytes(block_count, 2, 'little')
        header_data[0x4:0x8] = struct.pack("<HH", width, height)
        colorbit_type2 = header_data[0xb]
        header_data[0xa:0xc] = struct.pack("<BB", colorbit_type1, colorbit_type2)
        print(datpath + " header with "+str(hex(fp.tell()))+" bytes")

        # load the injected picture to buffer
        raw_stream = BytesIO()
        for y in range(height):
            for x in range(width):
                if  color_channel == 4 : # RGBA8888
                    b, g, r, a = img[y][x]
                    px_byte = struct.pack("<BBBB", (r+1)%256, (g+1)%256, (b+1)%256, (a+1)%256)
                elif color_channel == 3 : # RGB888
                    b, g, r = img[y][x]
                    px_byte = struct.pack("<BBB", (r+1)%256, (g+1)%256, (b+1)%256)
                elif color_channel == 1: # color panel
                    min_i = 0
                    min_d = np.dot(img[y][x]-color_panel[0])
                    for i in range(1, color_panel.shape[0]):
                        d = np.dot(img[y][x]-color_panel[0])
                        if d < min_d:
                            min_d = d
                            min_i = i
                        if d==0:
                            break
                    px_byte = struct.pack((d+1)%256)
                raw_stream.write(px_byte)
        print(inpath + " in buffer with "+str(raw_stream.tell())+" bytes")
    
        # compressed block
        decompressed_len = raw_stream.tell()
        compressed_len = 0
        compressed_stream = BytesIO()
        raw_stream.seek(0)
        arr_rawsize = []
        arr_cpsize = [] # compressed size
        rawsize = math.ceil(decompressed_len/block_count)
        for idx in range(block_count):
            if idx >= block_count-1: 
               rawsize = decompressed_len - rawsize*idx
            data_raw = bytearray(raw_stream.read(rawsize))

            if colorbit_type2==0x02:   # delta encoding
                px_num = len(data_raw) / color_channel
                linebytes_num = width * color_channel
                preline = bytearray(data_raw[0:linebytes_num])
                for h in range(1, math.ceil(px_num/width)):
                    if (h+1) * linebytes_num < len(data_raw):
                        length = linebytes_num
                    else: length = len(data_raw) % linebytes_num
                    curline = bytearray(data_raw[h*linebytes_num: h*linebytes_num+length])
                    for i in range(length):
                        data_raw[h*linebytes_num + i]  = (curline[i] - preline[i] + 1) % 256
                    preline = curline
            
            data_compressed = lzw_compress(bytes(data_raw))
            arr_cpsize.append(len(data_compressed))
            arr_rawsize.append(rawsize)
            compressed_len += arr_cpsize[-1]
            compressed_stream.write(data_compressed)
            print("lzw block %d, cpsize=%d rawsize=%d compressed"%(idx, arr_cpsize[-1], arr_rawsize[-1]))
        header_data[-8:] = struct.pack("<II", decompressed_len, compressed_len)
        header_data[-12:-10] = struct.pack("<H", block_count*8+8+4) # unkown 8
        header_data[-20:-16] = struct.pack("<I", compressed_len + len(header_data)) # unkown 7

    # write to rebuild datpath
    with open(outpath, 'wb') as fp:
        fp.write(header_data)
        for idx in range(block_count):
            fp.write(struct.pack("<II", arr_cpsize[idx], arr_rawsize[idx]))
        fp.write(compressed_stream.getbuffer())

def debug():
    # inpath = r"D:\MAKE\Reverse\Air_project\intermediate\picture_analyze\043_9C04A45.dat"
    # decode_dat(inpath, inpath+".png")

    #inpath = r"D:\MAKE\Reverse\Air_project\intermediate\picture_analyze\065_1FAB6A2.dat"
    #decode_dat(inpath, inpath+".png")
    inpath = r"D:\MAKE\Reverse\Air_project\intermediate\picture_analyze\043_9C04A45.dat"
    encode_dat(inpath+"2.png", inpath, inpath+"rebuild.dat")
    decode_dat(inpath+"rebuild.dat", inpath+"rebuild.png")

def main():
    if len(os.sys.argv) <= 2:
        print("port_dat d datpath [pngpath]")
        print("port_dat e pngpath basedatpath [outdatpath]")
        return 0

    if os.sys.argv[1].lower() == 'd':
        outpath = "out.png" if len(os.sys.argv)<=3 else os.sys.argv[3]
        decode_dat(os.sys.argv[2], outpath)
    elif os.sys.argv[1].lower() == 'e':
        pngpath = os.sys.argv[2]
        basedatpath = os.sys.argv[3]
        outpath = "out.dat" if len(os.sys.argv)<=4 else os.sys.argv[4]
        encode_dat(pngpath, basedatpath, outpath)
    else: print("invalid parameter")

if __name__=="__main__":
    #debug()
    main()