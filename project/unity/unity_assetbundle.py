"""
export or import objects from unity asset bundle
  v0.2.2, developed by devseed

thirdparty:
  UnityPy 1.22.3 (https://github.com/K0lb3/UnityPy/tree/bfea10a8d4f40296ef353b8464baf9a2a54574c5)
"""

import os
import glob
import json
import argparse
import UnityPy
from PIL import Image

def parse_pathordir(pathordir, pattern):
    inpaths = []
    if os.path.isfile(pathordir): 
        indir = os.path.dirname(pathordir)
        inpaths.append(pathordir)
    else: 
        indir = pathordir
        inpaths = glob.glob(os.path.join(pathordir, pattern), recursive=True)
    return indir, inpaths

def ensure_outpath(outpath):
    suboutdir = os.path.dirname(outpath)
    if not os.path.exists(suboutdir): os.makedirs(suboutdir)

def list_asset(pathordir, selects=None, searchpattern="**/*.assetbundle"):
    indir, inpaths = parse_pathordir(pathordir, searchpattern)
    print("file,container,pathid,name,type")
    for fpath in inpaths:
        rpath = os.path.relpath(fpath, indir).replace("\\", "/")
        env = UnityPy.load(fpath)
        for obj in env.objects:
            if selects and obj.type.name not in selects: continue

            if obj.type.name == "Texture2D":
                data = obj.read()
                if data.m_CompleteImageSize==0: continue
                print(f"{rpath},{obj.container},pathid{obj.path_id},{data.m_Name},Texture2D")
            
            elif obj.type.name == "MonoBehaviour": 
                if not obj.serialized_type.node: continue
                tree = obj.read_typetree()
                print(f"{rpath},{obj.container},pathid{obj.path_id},{tree['m_Name']},MonoBehaviour")
            
            elif obj.type.name == "TextAsset": 
                data = obj.read()
                print(f"{rpath},{obj.container},pathid{obj.path_id},{data.m_Name},TextAsset")

            elif obj.type.name == "AssetBundle": 
                data = obj.read()
                print(f"{rpath},{obj.container},pathid{obj.path_id},{data.m_Name},AssetBundle")
        
            elif obj.type.name == "Font": 
                data = obj.read()
                print(f"{rpath},{obj.container},pathid{obj.path_id},{data.m_Name},Font")

def export_asset(inpath, outdir=None, selects=None):
    env = UnityPy.load(inpath)
    for i, obj in enumerate(env.objects):
        if selects and obj.type.name not in selects: continue
        
        if obj.type.name == "Texture2D":
            data = obj.read()
            if data.m_CompleteImageSize==0: continue
            outpath = os.path.join(outdir, data.m_Name + ".png")
            ensure_outpath(outpath)
            try:
                data.image.save(outpath)
                print(f"export {i+1}/{len(env.objects)} {obj.container},{obj.path_id},{data.m_Name},Texture2D")
            except Exception as e:
                print(f"failed {e}, {i+1}/{len(env.objects)} {obj.container},{obj.path_id},{data.m_Name},Texture2D")
        
        elif obj.type.name == "MonoBehaviour":
            if not obj.serialized_type.node: continue
            tree = obj.read_typetree()
            # add pathid prefix to avoid "-" in shell
            outpath = os.path.join(outdir, f"pathid{obj.path_id}.json")
            ensure_outpath(outpath)
            with open(outpath, "wt", encoding = "utf8") as fp:
                json.dump(tree, fp, ensure_ascii = False, indent = 4)
            print(f"export {i+1}/{len(env.objects)} {obj.container},{obj.path_id},{tree['m_Name']},MonoBehaviour")
        
        elif obj.type.name == "TextAsset":
            data = obj.read()
            if len(data.m_Script)==0 or len(data.m_Name)==0: continue
            outpath = os.path.join(outdir, f"{data.m_Name}")
            ensure_outpath(outpath)
            with open(outpath, "wb") as fp:
                fp.write(data.m_Script.encode("utf-8", "surrogateescape"))
            print(f"export {i+1}/{len(env.objects)} {obj.container},{obj.path_id},{data.m_Name},TextAsset")
        
        elif obj.type.name == "Font":
            data = obj.read()
            if not data.m_FontData: continue
            ext= ".otf" if data.m_FontData[0:4] == b"OTTO" else ".ttf"
            outpath = os.path.join(outdir, f"{data.m_Name}{ext}")
            ensure_outpath(outpath)
            with open(outpath, "wb") as fp:
                fp.write(bytes(data.m_FontData))
            print(f"export {i+1}/{len(env.objects)} {obj.container},{obj.path_id},{data.m_Name},Font")

        elif obj.type.name == "AssetBundle":
            data = obj.read()
            print(f"nonexport {i+1}/{len(env.objects)} {obj.container},{obj.path_id},{data.m_Name},AssetBundle")

def import_asset(inpath, indir, outpath=None, selects=None):
    def _get_target(targetname):
        targetpath = os.path.join(indir, targetname)
        if not os.path.exists(targetpath): 
            targetpath = os.path.join(indir, obj.type.name, targetname)
            if not os.path.exists(targetpath): return None
        return targetpath

    env = UnityPy.load(inpath)
    for i, obj in enumerate(env.objects):
        if selects and obj.type.name not in selects: continue
        
        if obj.type.name == "Texture2D":
            data = obj.read()
            if data.m_CompleteImageSize==0: continue
            targetpath = _get_target(data.m_Name + ".png")
            if not targetpath: continue
            try:
                imgpil = Image.open(targetpath)
                data.image = imgpil
                data.save()
                print(f"import {i+1}/{len(env.objects)} {obj.container},{obj.path_id},{data.m_Name},Texture2D")
            except Exception as e:
                print(f"failed {e}, {i+1}/{len(env.objects)} {obj.container},{obj.path_id},{data.m_Name},Texture2D")
        
        elif obj.type.name == "MonoBehaviour":
            if not obj.serialized_type.node: continue
            targetpath = _get_target(f"pathid{obj.path_id}.json")
            if not targetpath: continue
            with open(targetpath, "rt", encoding = "utf8") as fp:
                tree = json.load(fp)
            obj.save_typetree(tree)
            print(f"import {i+1}/{len(env.objects)} {obj.container},{obj.path_id},{tree['m_Name']},MonoBehaviour")
        
        elif obj.type.name == "TextAsset":
            data = obj.read()
            if len(data.m_Script)==0 or len(data.m_Name)==0: continue
            targetpath = _get_target(f"{data.m_Name}")
            if not targetpath: continue
            with open(targetpath, "rb") as fp:
                data.m_Script = fp.read().decode("utf-8", "surrogateescape")
            data.save()
            print(f"import {i+1}/{len(env.objects)} {obj.container},{obj.path_id},{data.m_Name},TextAsset")

        elif obj.type.name == "Font":
            data = obj.read()
            if not data.m_FontData: continue
            ext= ".otf" if data.m_FontData[0:4] == b"OTTO" else ".ttf"
            targetpath = _get_target(f"{data.m_Name}{ext}")
            if not targetpath: continue
            with open(targetpath, "rb") as fp:
                data.m_FontData = list(fp.read())
            data.save()
            print(f"import {i+1}/{len(env.objects)} {obj.container},{obj.path_id},{data.m_Name},Font")

    if outpath:
        outdir = os.path.dirname(outpath)
        if not os.path.exists(outdir): os.makedirs(outdir)
        with open(outpath, "wb") as fp:
            fp.write(env.file.save())

def export_assert_multi(inpath, outdir=None, selects=None, searchpattern="**/*.assetbundle"):
    indir, inpaths = parse_pathordir(inpath, searchpattern)
    for fpath in inpaths:
        rpath = os.path.relpath(fpath, indir).replace("\\", "/") 
        targetoutdir = outdir
        if os.path.isdir(inpath):  
            targetoutdir = os.path.join(outdir, os.path.splitext(rpath)[0])
        export_asset(fpath, targetoutdir, selects=selects)

def import_asset_multi(abpath, indir, outpath=None, selects=None, searchpattern="**/*.assetbundle"):
    abdir, abpaths = parse_pathordir(abpath, searchpattern)
    for fpath in abpaths:
        rpath = os.path.relpath(fpath, abdir).replace("\\", "/") 
        targetindir = indir
        targetoutfile = outpath
        if os.path.isdir(abpath):
            targetindir = os.path.join(indir, os.path.splitext(rpath)[0])
            targetoutfile = os.path.join(outpath, rpath)
        import_asset(fpath, targetindir, targetoutfile, selects=selects)

def cli(cmdstr=None):
    parser = argparse.ArgumentParser(description=
            "Unity assetbundle cli tools for batch operation"
            "\n  v0.2.2, developed by devseed")
    parser.add_argument("method", choices=["list", "export", "import"], help="operation method")
    parser.add_argument("abpath", help="asssetbulde path or dir")
    parser.add_argument("--indir", "-i", default=None, help="import dir")
    parser.add_argument("--outpath", "-o", default="out", help="output path or dir")
    parser.add_argument("--selects", "-s", default=None, help="select types with comma, such as Texture2D,TextAsset")
    parser.add_argument("--searchpattern", default="**/*.assetbundle", help="explorer assertbundle pattern")
    args = parser.parse_args(cmdstr.split(" ") if cmdstr else None)
    
    method, selects, searchpattern = args.method, args.selects, args.searchpattern
    abpath, outpath, indir = args.abpath, args.outpath, args.indir
    if selects is not None: selects = selects.split(",")
    if method == "list":
        list_asset(abpath, selects=selects, searchpattern=searchpattern)
    elif method == "export":
        export_assert_multi(abpath, outpath, selects=selects, searchpattern=searchpattern)
    elif method == "import":
        if indir is None: 
            raise ValueError(f"need to specific --indir (import dir)")
        import_asset_multi(abpath,indir, outpath, selects=selects, searchpattern=searchpattern)
    else: raise ValueError(f"unknow operation {method}")

if __name__ == "__main__":
    cli()

"""
history
v0.1, initial version
v0.2, add MonoBehaviour and TextAsset
v0.2.1, add font
v0.2.2, add more options
"""