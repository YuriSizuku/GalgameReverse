# -*- coding: utf-8 -*-
"""
    for nature valaciton chs localization, 
    renaming sjis to crc32
    v0.1, developed by devseed
"""

import os
import shutil
import zlib
import codecs
import re

def renmae_iamge(image_dir, ext=[".png"], rename_dir=""):
    file_map = dict()
    if rename_dir=="": rename_dir = os.path.join(image_dir, "rename")
    if not os.path.exists(rename_dir): os.makedirs(rename_dir)
    for file in os.listdir(image_dir):
        if os.path.splitext(file)[1].lower() not in ext: continue 
        rename_crc32 = "%08X" %zlib.crc32(file.encode("utf-8")) + ".png"
        file_map[os.path.splitext(file)[0]] = rename_crc32
        print(os.path.join(rename_dir, rename_crc32))
        shutil.copyfile(os.path.join(image_dir, file), os.path.join(rename_dir, rename_crc32))
        # print("%s -> %s" %(file, rename_crc32))
    return file_map

def rename_script(script_path, file_map, rename_path=""):
    print("processing file " + script_path + "...")
    if rename_path=="": rename_path = script_path
    lines = []
    with codecs.open(script_path, 'r', 'utf-8') as fp:
        lines = fp.readlines()
    flag = False
    for i, line in enumerate(lines):
        m = re.search(r"\[storage:(.+?),", line)
        if m!=None and m.group(1) in file_map:
            flag = True
            orgpath = m.group(1)
            dstpath = "imagechs/" + file_map[orgpath]
            lines[i] = lines[i].replace(orgpath, dstpath)
            print("%s -> %s" %(orgpath, dstpath))
            continue
        m = re.search(r"\[storage:\"(.+?)\",", line)
        if m!=None and m.group(1) in file_map:
            flag = True
            orgpath = m.group(1)
            dstpath = "imagechs/" + file_map[orgpath]
            lines[i] = lines[i].replace(orgpath, dstpath)
            print("%s -> %s" %(orgpath, dstpath))
            continue

    if flag:
        with codecs.open(rename_path, 'w', 'utf-8') as fp:
            fp.writelines(lines)

def main():
    intermediate_dir= r".\build\intermediate"
    image_dir = os.path.join(intermediate_dir, "imagechs")
    image_rename_dir = os.path.join(intermediate_dir, "imagechs_hased")
    script_dir = os.path.join(intermediate_dir, "data_rebuild")
    script_rename_dir = os.path.join(intermediate_dir, "data_rebuild_hased")
    file_map = renmae_iamge(image_dir, rename_dir=image_rename_dir)
    for file in os.listdir(script_dir):
        if os.path.splitext(file)[1] not in ['.csv']:
            continue
        rename_script(os.path.join(script_dir, file), file_map, 
        os.path.join(script_rename_dir, file))

if __name__ == '__main__':
    main()