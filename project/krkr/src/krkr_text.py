"""
batch convert the text encoding for krkr
  v0.2, developed by devseed
"""

import os
import sys
import fnmatch
import argparse

def convert_file(inapth, outpath, fromcode, tocode, ignore="from", newline: str="") -> bool:
    _fromcode = fromcode.replace("-bom", "")
    _tocode = tocode.replace("-bom", "")
    ignore_from = ignore == "form" or ignore == "both"
    ignore_to = ignore == "to" or ignore == "both"
    outdir = os.path.dirname(outpath)
    if not os.path.exists(outdir) and len(outdir) > 0: os.makedirs(outdir)

    with open(inapth, "r", encoding=_fromcode, newline=None, 
            errors="ignore" if ignore_from else "strict") as fp:
        try:
            lines = fp.readlines()
        except UnicodeDecodeError as e:
            return False
    
    if len(lines) > 0 and len(lines[0]) > 0:
        lines[0] = lines[0].lstrip('\ufeff')

    with open(outpath, "w", encoding=_tocode, newline=newline, 
            errors="ignore" if ignore_to else "strict") as fp:
        try:
            if "bom" in tocode: fp.write('\ufeff')
            fp.writelines(lines)
        except UnicodeEncodeError as e:
            return False

    return True

def convert_dir(indir, outdir, fromcode, tocode, 
        ignore="from", newline="", includes=None, excludes=None) -> int:
    count = 0
    for root, dirs, files in os.walk(indir):
        for file in files:
            inpath = os.path.join(root, file)
            relpath = os.path.relpath(inpath, indir)
            outpath = os.path.join(outdir, relpath)
            include_flag = True
            if excludes is not None:
                for t in excludes: 
                    if not fnmatch.fnmatch(relpath, t): continue # match glob
                    include_flag = False
                    break
            if includes is not None:
                include_flag = False
                for t in includes:
                    if not fnmatch.fnmatch(relpath, t): continue
                    include_flag = True
                    break
            if not include_flag: continue
            if convert_file(inpath, outpath, 
                    fromcode, tocode, ignore=ignore, newline=newline):
                count += 1
                print(f"CONVERT {relpath}")
            else: 
                if os.path.exists(outpath): os.remove(outpath)
                print(f"FAILED {relpath}")
    return count

def cli(cmdstr=None):
    parser = argparse.ArgumentParser(description="batch convert text encoding, v0.2, developed by devseed")
    parser.add_argument("inpath", help="file or directory")
    parser.add_argument("-o", "--outpath", default="out", help="file or directory")
    parser.add_argument("-f", "--from-code", metavar="encoding", default="sjis")
    parser.add_argument("-t", "--to-code", metavar="encoding", default="utf16-bom")
    parser.add_argument("-n", "--ignore", choices=["none", "from", "to", "both"], default="from", help="ignore coding error")
    parser.add_argument("-l", "--newline", choices=["origin", "lf", "crlf", "cr"], default="origin", help="change line encoding")
    parser.add_argument("-i", "--include", action="append", default=None, help="include pattern, such as *.txt")
    parser.add_argument("-e", "--exclude", action="append", default=None, help="exclude pattern, such as *.png")
    
    if cmdstr is None and len(sys.argv) < 2:
        parser.print_help()
        return
    
    args = parser.parse_args(cmdstr.split(' ') if cmdstr else None)
    print(args)

    newline = ""
    if args.newline.lower() == "origin": newline = ""
    elif args.newline.lower() == "cr": newline = "\r"
    elif args.newline.lower() == "lf": newline = "\n"
    elif args.newline.lower() == "crlf": newline = "\r\n"
    inpath, outpath = args.inpath, args.outpath
    fromcode, tocode = args.from_code, args.to_code
    ignore = args.ignore
    includes, excludes = args.include, args.exclude

    if not os.path.exists(inpath):
        raise FileExistsError(f"{inpath} is invalid")
    if os.path.isfile(inpath): 
        res = convert_file(inpath, outpath, fromcode, tocode, ignore=ignore, newline=newline)
        print(f'{"CONVERT" if res else "FAILED"} {os.path.basename(inpath)}')
    else: convert_dir(inpath, outpath, fromcode, tocode, 
            ignore=ignore, newline=newline, includes=includes, excludes=excludes)

if __name__ == "__main__":
    cli()

""" history
v0.1, krkr_sjis2utf16
v0.2, remake with new cli and add more options
"""