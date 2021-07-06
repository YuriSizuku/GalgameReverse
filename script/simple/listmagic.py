import csv
import os
import sys

def read_maigic(fp):
    chars = []
    i = 0
    while True:
        c = fp.read(1)
        if c.isalnum() is False:
            return "".join(chars)
        if c==b'\0' or i>10 :
            return "".join(chars)
        chars.append(chr(c[0]))
        i += 1

if __name__ == "__main__":
    arr = []
    for root, dirs, files in os.walk(sys.argv[1]):
        for name in files:
            path = os.path.join(root, name)
            relpath = os.path.relpath(path, sys.argv[1])
            print(relpath)
            with open(path, 'rb') as fp:
                magic = read_maigic(fp)
                if magic == [] or magic == "": magic = os.path.splitext(path)[1]
            fsize = os.path.getsize(path)
            print(relpath, magic, fsize)
            arr.append((relpath, magic, fsize))
    with open(os.path.basename(sys.argv[1]+"_magiclist.csv"), 'w', newline='') as fp:
        w = csv.writer(fp)
        w.writerows(arr)