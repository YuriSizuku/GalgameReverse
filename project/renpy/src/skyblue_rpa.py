"""
extract *.blend file for The Other Side of the Sky
    v0.1, developed by devseed
"""

import os
import sys
import io
import zlib
import mmap
import pickle

# pickle.py
PROTOCOL = 2
REWRITE_NODES = {}
import functools
import datetime

def make_datetime(cls, *args, **kwargs):
    """
    Makes a datetime.date, datetime.time, or datetime.datetime object
    from a surrogateescaped str. This is used when unpickling a datetime
    object that was first created in Python 2.
    """

    if (len(args) == 1) and isinstance(args[0], str):
        data = args[0].encode("utf-8", "surrogateescape")
        return cls.__new__(cls, data.decode("latin-1"))

    return cls.__new__(cls, *args, **kwargs)

class Unpickler(pickle.Unpickler):
    date = functools.partial(make_datetime, datetime.date)
    time = functools.partial(make_datetime, datetime.time)
    datetime = functools.partial(make_datetime, datetime.datetime)

    def find_class(self, module, name):
        if module == "datetime":
            if name == "date":
                return self.date
            elif name == "time":
                return self.time
            elif name == "datetime":
                return self.datetime

        if module == "_ast" and name in REWRITE_NODES:
            return REWRITE_NODES[name]

        return super().find_class(module, name)

def load(f):
    up = Unpickler(f, fix_imports=True, encoding="utf-8", errors="surrogateescape")
    return up.load()

def loads(s):
    return load(io.BytesIO(s))

def dump(o, f, highest=False):
    pickle.dump(o, f, pickle.HIGHEST_PROTOCOL if highest else PROTOCOL)

def dumps(o, highest=False):
    return pickle.dumps(o, pickle.HIGHEST_PROTOCOL if highest else PROTOCOL)

# loader.py
class RPAv3ArchiveHandler(object):
    """
    Archive handler handling RPAv3 archives.
    """

    archive_extension = ".blend"

    @staticmethod
    def get_supported_extensions():
        return [ ".blend" ]

    @staticmethod
    def get_supported_headers():
        return [ b"WJZ-4.9 " ]

    @staticmethod
    def read_index(infile: io.BytesIO) -> dict:
        l = infile.read(40)
        offset = int(l[8:24], 16)
        key = int(l[25:33], 16)
        infile.seek(offset)
        index = loads(zlib.decompress(infile.read()))

        def start_to_bytes(s):
            if not s:
                return b''

            if not isinstance(s, bytes):
                s = s.encode("latin-1")

            return s

        # Deobfuscate the index.
        for k in index.keys():
            if len(index[k][0]) == 2:
                index[k] = [ (offset ^ key, dlen ^ key) for dlen, offset in index[k] ]
            else:
                index[k] = [ (offset ^ key, dlen ^ key, start_to_bytes(start)) for dlen, offset, start in index[k] ]

        return index
    
def extract_rpa(inpath, outdir="out"):
    fp = open(inpath, "rb")
    infile = mmap.mmap(fp.fileno(), 0, access=mmap.ACCESS_READ)
    index = RPAv3ArchiveHandler.read_index(infile)

    for entry_name, v in index.items():
        outpath = os.path.join(outdir, entry_name)
        if not os.path.exists(os.path.dirname(outpath)) :
            os.makedirs(os.path.dirname(outpath))
        with open(outpath, "wb") as fp2:
            for j, (offset, fsize, uknow) in enumerate(v):
                print(f"{entry_name} chunck={j} offset=0x{offset:x} fsize=0x{fsize:x}")
                fp2.write(infile[offset: offset + fsize])

    infile.close()
    fp.close()

def debug():
    pass

def cli(argv=sys.argv):
    if len(argv) < 2:
        print("skyblue_rpa inpath [outdir] // inpath wjz *.blend")

    inpath = argv[1]
    outdir = argv[2] if len(argv) > 2 else os.path.dirname(inpath)

    extract_rpa(inpath, outdir)

if __name__ == "__main__":
    cli()