"""
krkr hxv4 hash tool for filehash and dirhash
see also krkr_hxv4_dumphash.cpp for dynamic dump hash
  v0.1, developed by devseed
"""

__version__ = "v0.1.1"
__description__ = f"krkr hxv4 hash tool, {__version__}, by devseed"

import os
import sys
import shlex
import shutil
import argparse
from hashlib import blake2s
from siphash import SipHash_2_4

def calc_dirhash(s: str, seed="xp3hnp") -> bytes:
    h = SipHash_2_4(b"\x00" * 16)
    h.update(s.encode("utf-16le"))
    h.update(seed.encode("utf-16le"))
    return h.digest()

def calc_filehash(s: str, seed="xp3hnp") -> bytes:
    h = blake2s(digest_size=32)
    h.update(s.encode("utf-16le"))
    h.update(seed.encode("utf-16le"))
    return h.digest()

def load_list(inpath, encoding="utf-16le", unique=False):
    namelist = []
    with open(inpath, "rt", encoding=encoding) as fp:
        lines = fp.readlines()
    lines[0] = lines[0].lstrip('\ufeff')
    for line in lines:
        name = line.rstrip("\n").rstrip("\r")
        namelist.append(name)
    if unique: namelist = list(set(namelist))
    return namelist

def load_match(inpath, encoding="utf-16le"):
    with open(inpath, "rt", encoding=encoding) as fp:
        lines = fp.readlines()
    lines[0] = lines[0].lstrip('\ufeff')
    inlist, outlist = [], []
    for line in lines:
        i, o = line.rstrip("\n").rstrip("\r").split(",")
        inlist.append(i)
        outlist.append(o)
    return inlist, outlist

def save_match(inlist, outlist, outpath, encoding="utf-16le"):
    lines = [f"{i},{o}\n"for i, o in zip(inlist, outlist)]
    with open(outpath, "wt", encoding=encoding, newline="\r\n") as fp:
        if encoding=="utf-16le": fp.write("\ufeff")
        fp.writelines(lines)
    return lines

def rename_match(inlist, outlist, outdir):

    dircount, filecount = 0, 0
    pathmap = dict()
    for i, o in zip(inlist, outlist):
        pathmap[o] = i
    for root, dirs, files in os.walk(outdir):
        for f in files:
            f = f.lower()
            if f not in pathmap: continue
            print(f"{f} -> {pathmap[f]}")
            filecount += 1
            shutil.move(os.path.join(root, f), os.path.join(root, pathmap[f]))

    for root, dirs, files in os.walk(outdir):
        for d in dirs:
            d = d.lower()
            if d not in pathmap: continue
            src = os.path.join(root, d)
            dst = os.path.join(root, pathmap[d])
            print(f"{d} -> {pathmap[d]}")
            if os.path.exists(dst):
                shutil.copytree(src, dst, dirs_exist_ok=True)
                shutil.rmtree(src)
            else: shutil.move(src, dst)
            dircount += 1

    print(f"[rename_match] {outdir} with {filecount} files, {dircount} dirs")

def cli(cmdstr=None):
    p = argparse.ArgumentParser(description=__description__)
    p.add_argument("method", choices=["file", "dir", "rename"])
    p.add_argument("inpath", help="string or @filepath")
    p.add_argument("-o", "--outpath", default=None)
    p.add_argument("-e", "--encoding", default="utf-16le", help="inpath and outpath encoding")
    p.add_argument("--seed", default="xp3hnp", help="hxv4 hash seed")
    p.add_argument("--unique", action="store_true", help="remove duplicate path")
    if cmdstr is None and len(sys.argv) < 2:
        p.print_help()
        return

    args = p.parse_args(shlex.split(cmdstr, posix=False) if cmdstr is not None else None)
    method, inpath, outpath = args.method, args.inpath, args.outpath
    encoding, seed, unique = args.encoding, args.seed, args.unique

    if method in {"file", "dir"}:
        inlist = []
        outlist = []
        if method == "dir": f_calc = calc_dirhash
        elif method == "file": f_calc = calc_filehash
        if inpath.startswith("@"):
            inlist.extend(load_list(inpath[1:], encoding, unique))
            print(f"[{f_calc.__name__}] load {len(inlist)} paths in {inpath[1:]}")
            for i in inlist: outlist.append(f_calc(i, seed).hex())
        else:
            inlist.append(inpath)
            outlist.append(f_calc(inpath, seed).hex())
            print(outlist[0])

        if outpath:
            save_match(inlist, outlist, outpath, encoding=encoding)

    elif method == "rename":
        if inpath.startswith("@"):
            inlist, outlist = load_match(inpath[1:], encoding=encoding)
        else:
            i, o = inpath.split(",")
            inlist.append(i)
            outlist.append(o)
        rename_match(inlist, outlist, outpath)

if __name__ == "__main__":
    cli()