import os
import numpy as np
import cv2
import csv

"""
criware xtx font extract or rebuild, by devseed
inspired by https://github.com/vn-tools/arc_unpacker/issues/54

v0.1  xtx font type 01, decode, encode finished
      Tested in iwaihime font48.xtx, charactor size 48X48, GRAY4
"""
block_size = 48
intensity_map = (
        0b00000000, 0b00010001, 0b00100010, 0b00110011,
        0b01000100, 0b01010101, 0b01100110, 0b01110111,
        0b10001000, 0b10011001, 0b10101010, 0b10111011,
        0b11001100, 0b11011101, 0b11101110, 0b11111111)

def get_x(i, width, level): 
    # level means nesting times
    v1 = (level >> 2) + (level >> 1 >> (level >> 2))
    v2 = i << v1
    # 8X8 3f, 
    v3 = (v2 & 0x3F) + ((v2 >> 2) & 0x1C0) + ((v2 >> 3) & 0x1FFFFE00)
    return ((((level << 3) - 1) & ((v3 >> 1) ^ ((v3 ^ (v3 >> 1)) & 0xF))) >> v1)+  ((((((v2 >> 6) & 0xFF) + ((v3 >> (v1 + 5)) & 0xFE)) & 3)
            + (((v3 >> (v1 + 7)) % (((width + 31)) >> 5)) << 2)) << 3)

def get_y(i, width, level):
    v1 = (level >> 2) + (level >> 1 >> (level >> 2))
    v2 = i << v1
    v3 = (v2 & 0x3F) + ((v2 >> 2) & 0x1C0) + ((v2 >> 3) & 0x1FFFFE00)
    return ((v3 >> 4) & 1) + ((((v3 & ((level << 6) - 1) & -0x20)
            + ((((v2 & 0x3F)
                + ((v2 >> 2) & 0xC0)) & 0xF) << 1)) >> (v1 + 3)) & -2) + ((((v2 >> 10) & 2) + ((v3 >> (v1 + 6)) & 1)
            + (((v3 >> (v1 + 7)) // ((width + 31) >> 5)) << 2)) << 3)

def xtx_tex12gray(data, height, width, aligned_height, aligned_width):
    gray = np.zeros([width*2, height*2], dtype=np.uint8) # exchange width height

    print("%dX%d xtx, %d bytes-> %dX%d Gray"%(width, height, len(data), height*2, width*2 ))
    for i in range(height*width):
        abs_x = get_x(i, width, 2)
        abs_y = get_y(i, width, 2)
        if abs_y >= height or abs_x >= width:
            continue

        # each 2 byte containes 4 gray pixel
        idx = i * 2
        block_x = (abs_x // block_size) * block_size
        block_y = (abs_y // block_size) * block_size
        x = abs_x % block_size
        y = abs_y % block_size
        target_y = block_y + y
        target_x1 = block_x * 4 + x; # each block(48X48) has 4 cordinate
        target_x2 = block_x * 4 + x + block_size;
        target_x3 = block_x * 4 + x + block_size * 2;
        target_x4 = block_x * 4 + x + block_size * 3;
        gray[target_y][target_x1] = intensity_map[data[idx] >> 4]
        gray[target_y][target_x2] = intensity_map[data[idx] & 0xf]
        gray[target_y][target_x3] = intensity_map[data[idx+1] >> 4]
        gray[target_y][target_x4] = intensity_map[data[idx+1] & 0xf]
    return gray

def gray2xtx_tex1(gray):
    height, width = gray.shape
    data = bytearray(height*width//2)
    print("%dX%d Gray -> %dX%d xtx, %d bytes"%(width, height, height//2, width//2, len(data)))

    # revert height, width and make to half of
    for i in range(height//2*width//2):
        abs_x = get_x(i, height//2, 2)
        abs_y = get_y(i, height//2, 2)
        if abs_y >= width//2 or abs_x >= height//2:
            continue

        # each 2 byte containes 4 gray pixel
        idx = i * 2
        block_x = (abs_x // block_size) * block_size
        block_y = (abs_y // block_size) * block_size
        x = abs_x % block_size
        y = abs_y % block_size
        target_y = block_y + y
        target_x1 = block_x * 4 + x; # each block(48X48) has 4 cordinate
        target_x2 = block_x * 4 + x + block_size;
        target_x3 = block_x * 4 + x + block_size * 2;
        target_x4 = block_x * 4 + x + block_size * 3;

        # just simply use the gray to rebuild font, also can use intensity map
        data[idx] = (gray[target_y][target_x1]*15//255<<4) + \
                      gray[target_y][target_x2]*15//255
        data[idx+1] = (gray[target_y][target_x3]*15//255<<4) + \
                      gray[target_y][target_x4]*15//255
    return data

def xtx_extract(inpath, outpath="out.png"):
    with open(inpath, "rb") as fp:
        magic = fp.read(4)
        if magic!=b"xtx\0":
            print("not xtx format!")
            return None
        type = int.from_bytes(fp.read(1), 'little')
        fp.seek(3, 1)
        aligned_width = int.from_bytes(fp.read(4), 'big')
        aligned_height = int.from_bytes(fp.read(4), 'big')
        width = int.from_bytes(fp.read(4), 'big')
        height = int.from_bytes(fp.read(4), 'big')
        offset_x = int.from_bytes(fp.read(4), 'big')
        offset_y = int.from_bytes(fp.read(4), 'big')
        fp.seek(0x20)
        data = fp.read()
    
    if type == 1:
        gray = xtx_tex12gray(data, height, width, aligned_height, aligned_width)
    else:
        print("Unsupported xtx type " + str(type))
    cv2.imwrite(outpath, gray)

def xtx_font_build(inpath, outpath="rebuild.xtx"):
    gray = cv2.imread(inpath, cv2.IMREAD_GRAYSCALE)
    height, width = gray.shape
    with open(outpath, 'wb') as fp:
        fp.write(b"xtx\0")
        fp.write(b"\x01\x00\x00\x00")
        fp.write(int.to_bytes(height//2, 4, 'big'))
        fp.write(int.to_bytes(width//2, 4, 'big'))
        fp.write(int.to_bytes(height//2, 4, 'big'))
        fp.write(int.to_bytes(width//2, 4, 'big'))
        fp.write(int.to_bytes(0, 4, 'big'))
        fp.write(int.to_bytes(0, 4, 'big'))
        data = gray2xtx_tex1(gray)
        fp.write(data)

def main():
    if len(os.sys.argv) <= 2:
        print("xtxfont d xtxpath [pngpath]")
        print("xtxfont e pngpath [xtxpath]")
        return 0
    
    if os.sys.argv[1].lower() == 'd':
        outpath = "out.png" if len(os.sys.argv)<=3 else os.sys.argv[3]
        xtx_extract(os.sys.argv[2], outpath)
    elif os.sys.argv[1].lower() == 'e':
        outpath = "out.xtx" if len(os.sys.argv)<=3 else os.sys.argv[3]
        xtx_font_build(os.sys.argv[2], outpath)
    else: print("invalid parameter")

def showtable():
    width = 48
    height = 96
    lines = []
    for i in range(height*2):
        lines.append(width*2*[0])
    for i in range(width * height):
        x = get_x(i, width, 2)
        y = get_y(i, width, 2)
        lines[y][x] = str(i)
        print(i, y ,x)
    with open('position.csv', 'w', newline='') as fp:
        f_csv = csv.writer(fp)
        f_csv.writerows(lines)


def debug():
    showtable()
    pass

if __name__ == "__main__":
    main()