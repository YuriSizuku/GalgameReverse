import cv2 
import numpy as np
import argparse
import math
import struct
import os

"""
texture.py, by devseed
something about texture and picture convert

v0.1 initial version with RGBA8888， RGB332 convert
v0.1.1 added BGR mode
"""
texture_size = {"RGBA8888":4, "RGB5A1": 2, "RGB332":1, "RGBA2222":1}

def raw2gray(data, width):
    height = math.ceil(len(data) /  width)
    gray = np.zeros((height, width), dtype=np.uint8)
    print(width, height)
    for row in range(height):
        for col in range(width):         
            start = row*width + col       
            if start > len(data) -1:
                print(row, col, start, " out of range")
                break
            gray[row][col] = struct.unpack("<B", data[start:start+1])[0] 
    return gray

def gray2raw(gray):
    height, width = gray.shape
    data = bytearray(height*width)
    print(width, height, len(data))
    for row in range(height):
        for col in range(width):  
            start = row*width + col
            data[start:start+1] = struct.pack("<B", gray[row][col])
    return data

def raw2bgra(data, width, format="RGBA8888", *,compress_format="",is_bgr=False):
    pixel_size = texture_size[format]
    height = math.ceil(len(data) / (pixel_size * width))
    bgra = np.zeros((height, width, 4), dtype=np.uint8)
    print(width, height)
    for row in range(height):
        for col in range(width):                
            flag = 0
            start = (row*width + col) * pixel_size

            if format == "RGBA8888":
                if start > len(data) -4: 
                    flag = 1
                    print(row, col, start, " out of range")
                    break
                r, g, b, a = struct.unpack("<BBBB", data[start:start+4])
            
            elif format == "RGB332":
                if start > len(data) -1:
                    flag = 1
                    print(row, col, start, " out of range")
                    break
                a = 255
                d = struct.unpack("<B", data[start:start+1])[0] 
                r = round((d >> 5) * 255 / 7)
                g = round(((d >> 2) & 0b00000111) * 255 / 7)
                b = round((d & 0b00000011) * 255 / 3)

            elif format == "RGBA2222":
                if start > len(data) -1:
                    flag = 1
                    print(row, col, start, " out of range")
                    break
                d = struct.unpack("<B", data[start:start+1])[0] 
                r = round((d >> 6) * 255 / 3)
                g = round(((d >> 4) & 0b00000011) * 255 / 3)
                b = round(((d >> 2) & 0b00000011) * 255 / 3)
                a = round((d & 0b00000011) * 255 / 3)

            else: 
                print(format + " is invalid !")
                return None

            if is_bgr:
                t = r
                r = b
                b = t
            bgra[row][col] = np.array([b, g, r, a], dtype=np.uint8)
        
        if flag: break
    return bgra

def bgra2raw(bgra, format="RGBA8888", *, compress_format="", is_bgr=False):
    pixel_size = texture_size[format]
    height, width, channal = bgra.shape
    data = bytearray(height*width*pixel_size)
    print(width, height, len(data))
    for row in range(height):
        for col in range(width):       
            if channal == 4:
                b, g, r, a = bgra[row][col].tolist()
            else :
                b, g, r = bgra[row][col].tolist()
                a = 255
            if is_bgr:
                t = r
                r = b
                b = t
            start = (row*width + col) * pixel_size

            if format == "RGBA8888":
                data[start:start+4] = struct.pack("<BBBB", r, g, b, a)

            elif format == "RGB332":
                d = round(b * 3 /255) + (round(g * 7 /255)<<2) + (round(r * 7 /255)<<5)
                data[start:start+1] = struct.pack("<B", d)
            
            elif format == "RGBA2222":
                d = round(a * 3 /255) + (round(b * 3 /255)<<2) +  (round(g * 3 /255)<<4) + (round(r * 3 /255)<<6)
                data[start:start+1] = struct.pack("<B", d)
            
            else: 
                print(format + " is invalid !")
                return None
    return data

def texture2picture(inpath, width, outpath="out.png", format="RGBA8888", *,compress_format="", is_bgr=False, f_before=None):
    with open(inpath, "rb") as fp:
        print(inpath + " opened!")
        data = fp.read()
        if f_before: data = f_before(data)
        if format == "GRAY":
            gray = raw2gray(data, width)
            cv2.imwrite(outpath, gray)
        else:
            bgra = raw2bgra(data, width, format=format, compress_format=compress_format, is_bgr = is_bgr)
            cv2.imwrite(outpath, bgra)
        print(outpath + "picture extracted!")

def picture2texture(inpath, outpath=r".\out.bin", format="RGBA8888", *, compress_format="", is_bgr=False, f_after=None):
    if format == "GRAY":
        gray = cv2.imread(inpath, cv2.IMREAD_GRAYSCALE)
        print(inpath + " loaded!")
        data = gray2raw(gray)
    else:
        bgra = cv2.imread(inpath, cv2.IMREAD_UNCHANGED)
        print(inpath + " loaded!")
        data = bgra2raw(bgra, format, compress_format=compress_format, is_bgr=is_bgr)
    if f_after: data = f_after(data)
    with open(outpath, "wb") as fp:
        fp.write(data)
        print(outpath + "texture generated!")

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-b', '--build', action="store_true")
    parser.add_argument("-f", "--format", type=str, default="RGBA8888")
    parser.add_argument("-c", "--compress", type=str, default="")
    parser.add_argument("-o", "--outpath", type=str, default=r".\out.png")
    parser.add_argument("-w", "--width", type=int, default=2048)
    parser.add_argument('--bgr', action="store_true")
    parser.add_argument("inpath")
    args = parser.parse_args()
    if args.build:
        picture2texture(args.inpath, outpath=args.outpath, format=args.format, compress_format=args.compress, is_bgr=args.bgr)
    else:
        texture2picture(args.inpath, args.width, outpath=args.outpath, format=args.format, compress_format=args.compress, is_bgr=args.bgr)
        