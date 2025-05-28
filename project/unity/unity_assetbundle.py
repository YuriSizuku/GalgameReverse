"""
batch export or import objects from unity asset bundle
  v0.2.4, developed by devseed

tested games:
  Lost Smile, windows, 2018.4.15f1
  ときめきメモリアル～forever with you～, switch, 6000.0.29f1

thirdparty:
  UnityPy 1.22.3 (https://github.com/K0lb3/UnityPy/tree/bfea10a8d4f40296ef353b8464baf9a2a54574c5)
"""

import os
import sys
import glob
import json
import argparse
import UnityPy
from PIL import Image
from UnityPy.helpers.TypeTreeGenerator import TypeTreeGenerator

__VERSION__ = 240

DLL_DIR: str = None
GAME_DIR: str = None
GAME_VERSION: str = None

def init_unitypy(env: UnityPy.Environment):
    global DLL_DIR, GAME_DIR, GAME_VERSION
    if not DLL_DIR and not GAME_DIR and not GAME_VERSION: return
    if GAME_VERSION is None: GAME_VERSION = env.objects[0].assets_file.unity_version
    try: # needs to install typetreegeneratorapi
        generator = TypeTreeGenerator(GAME_VERSION)
        if GAME_DIR is not None: generator.load_local_game(GAME_DIR)
        elif DLL_DIR is not None: generator.load_local_dll_folder(DLL_DIR)
        env.typetree_generator = generator
    except ImportError as e:
        print(e, file=sys.stderr)

def parse_pathordir(pathordir, pattern):
    inpaths = []
    if os.path.isfile(pathordir): 
        indir = os.path.dirname(pathordir)
        inpaths.append(pathordir)
    else: 
        indir = pathordir
        inpaths = glob.glob(os.path.join(pathordir, pattern), recursive=True)
    return indir, inpaths

def find_outpath(outdir, names, ext=""):
    for name in names:
        if os.path.basename(name) == "": continue
        outpath = os.path.join(outdir, name+ext)
        if os.path.exists(outpath): continue
        targetdir = os.path.dirname(outpath)
        if not os.path.exists(targetdir): os.makedirs(targetdir)
        return outpath
    return None

def find_inpath(indir, names, ext=""):
    for name in names:
        if os.path.basename(name) == "": continue
        inpath = os.path.join(indir, name+ext)
        if os.path.exists(inpath): return inpath
    return None

def make_names(abname, name, pathid, seq, namestyle="name", isimport=False):
    outnames = []
    if namestyle == "namethenpathid": 
        if isimport:
            outnames.append(f"{name}pathid{pathid}")
            outnames.append(f"{name}")
        else:
            outnames.append(f"{name}")
            outnames.append(f"{name}pathid{pathid}")
    elif namestyle == "nameseq":
        outnames.append(f"{name}id{seq}")
    elif namestyle == "namepathid":
        outnames.append(f"{name}pathid{pathid}")
    elif namestyle == "seq":
        outnames.append(f"seq{seq}")
    elif namestyle == f"pathid":
        outnames.append(f"pathid{seq}")
    elif namestyle == "uabea":
        outnames.append(f"{name}-{abname}-{seq}")
    return outnames

def list_asset(pathordir, outpath=None, selects=None, searchpattern="**/*.assetbundle"):
    lines = []
    indir, inpaths = parse_pathordir(pathordir, searchpattern)
    lines.append("file,container,pathid,name,type")
    print(lines[-1])
    if selects is None: selects = {"Texture2D", "MonoBehaviour", "TextAsset", "Font"}
    for fpath in inpaths:
        rpath = os.path.relpath(fpath, indir).replace("\\", "/")
        env = UnityPy.load(fpath)
        init_unitypy(env)
        for obj in env.objects:
            if obj.type.name not in selects: continue
            try:
                data = obj.read()
                if obj.type.name == "Texture2D" and data.m_CompleteImageSize==0: continue
                lines.append(f"{rpath},{obj.container},pathid{obj.path_id},{data.m_Name},{obj.type.name}")
                print(lines[-1])
            except ValueError:
                pass

    if outpath: 
        with open(outpath, "w", encoding="utf8") as fp:
            fp.writelines([line + "\n" for line in lines])

def export_asset(inpath, outdir=None, selects=None, namestyle=None):
    env = UnityPy.load(inpath)
    init_unitypy(env)
    if selects is None: selects = {"Texture2D", "MonoBehaviour", "TextAsset", "Font"}
    for i, obj in enumerate(env.objects):
        if obj.type.name not in selects: continue
        try:
            data = obj.read()
        except ValueError as e:
            print(f"failed {e}, {i+1}/{len(env.objects)} {obj.container},{obj.path_id},{data.m_Name},{obj.type.name}")
        
        # add pathid prefix to avoid "-" in shell
        names = make_names(os.path.basename(inpath), data.m_Name, obj.path_id, i+1, namestyle)
        if obj.type.name == "Texture2D":
            if data.m_CompleteImageSize==0: continue
            outpath = find_outpath(outdir, names, ".png")
            if not outpath: continue
            try:
                data.image.save(outpath)
                print(f"export {i+1}/{len(env.objects)} {obj.container},{obj.path_id},{data.m_Name},{obj.type.name}")
            except Exception as e:
                print(f"failed {e},{i+1}/{len(env.objects)} {obj.container},{obj.path_id},{data.m_Name},{obj.type.name}")
        
        elif obj.type.name == "MonoBehaviour":
            try:
                tree = obj.read_typetree()
                names.append(tree["m_Name"])
                outpath = find_outpath(outdir, names, ".json")
                if not outpath: continue
                with open(outpath, "wt", encoding = "utf8") as fp:
                    json.dump(tree, fp, ensure_ascii=False, indent=4)
                print(f"export {i+1}/{len(env.objects)} {obj.container},{obj.path_id},{data.m_Name},{obj.type.name}")
            except Exception as e:
                print(f"failed {e},{i+1}/{len(env.objects)} {obj.container},{obj.path_id},{data.m_Name},{obj.type.name}")
        
        elif obj.type.name == "TextAsset":
            if len(data.m_Script)==0: continue
            outpath = find_outpath(outdir, names)
            if outpath is None: continue
            with open(outpath, "wb") as fp:
                fp.write(data.m_Script.encode("utf-8", "surrogateescape"))
            print(f"export {i+1}/{len(env.objects)} {obj.container},{obj.path_id},{data.m_Name},{obj.type.name}")
        
        elif obj.type.name == "Font":
            if not data.m_FontData: continue
            ext= ".otf" if data.m_FontData[0:4] == b"OTTO" else ".ttf"
            outpath = find_outpath(outdir, names, ext)
            if not outpath: continue
            with open(outpath, "wb") as fp:
                fp.write(bytes(data.m_FontData))
            print(f"export {i+1}/{len(env.objects)} {obj.container},{obj.path_id},{data.m_Name},{obj.type.name}")

        elif obj.type.name == "AssetBundle":
            print(f"noexport {i+1}/{len(env.objects)} {obj.container},{obj.path_id},{data.m_Name},AssetBundle")

def import_asset(inpath, indir, outpath=None, selects=None, namestyle=None):
    env = UnityPy.load(inpath)
    init_unitypy(env)
    if selects is None: selects = {"Texture2D", "MonoBehaviour", "TextAsset", "Font"}
    for i, obj in enumerate(env.objects):
        if obj.type.name not in selects: continue
        try:
            data = obj.read()
        except ValueError as e:
            pass
        
        names = make_names(os.path.basename(inpath), data.m_Name, obj.path_id, i+1, namestyle, isimport=True)
        othernames = [os.path.join(obj.type.name, x) for x in names]
        names.extend(othernames)
        if obj.type.name == "Texture2D":
            if data.m_CompleteImageSize==0: continue
            targetpath = find_inpath(indir, names, ".png")
            if not targetpath: continue
            try:
                imgpil = Image.open(targetpath)
                data.image = imgpil
                data.save()
                print(f"import {i+1}/{len(env.objects)} {obj.container},{obj.path_id},{data.m_Name},Texture2D")
            except Exception as e:
                print(f"failed {e}, {i+1}/{len(env.objects)} {obj.container},{obj.path_id},{data.m_Name},Texture2D")
        
        elif obj.type.name == "MonoBehaviour":
            targetpath = find_inpath(indir, names, ".json")
            if not targetpath: continue
            with open(targetpath, "rt", encoding = "utf8") as fp:
                tree = json.load(fp)
            obj.save_typetree(tree)
            print(f"import {i+1}/{len(env.objects)} {obj.container},{obj.path_id},{tree['m_Name']},MonoBehaviour")
        
        elif obj.type.name == "TextAsset":
            if len(data.m_Script)==0: continue
            targetpath = find_inpath(indir, names)
            if not targetpath: continue
            with open(targetpath, "rb") as fp:
                data.m_Script = fp.read().decode("utf-8", "surrogateescape")
            data.save()
            print(f"import {i+1}/{len(env.objects)} {obj.container},{obj.path_id},{data.m_Name},TextAsset")

        elif obj.type.name == "Font":
            if not data.m_FontData: continue
            ext= ".otf" if data.m_FontData[0:4] == b"OTTO" else ".ttf"
            targetpath = find_inpath(indir, names, ext)
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

def export_assert_multi(inpath, outdir=None, selects=None, searchpattern="**/*.assetbundle", namestyle=None):
    indir, inpaths = parse_pathordir(inpath, searchpattern)
    for fpath in inpaths:
        rpath = os.path.relpath(fpath, indir).replace("\\", "/") 
        targetoutdir = outdir
        if os.path.isdir(inpath):  
            targetoutdir = os.path.join(outdir, os.path.splitext(rpath)[0])
        export_asset(fpath, targetoutdir, selects=selects, namestyle=namestyle)

def import_asset_multi(abpath, indir, outpath=None, selects=None, searchpattern="**/*.assetbundle", namestyle=None):
    abdir, abpaths = parse_pathordir(abpath, searchpattern)
    for fpath in abpaths:
        rpath = os.path.relpath(fpath, abdir).replace("\\", "/") 
        targetindir = indir
        targetoutfile = outpath
        if os.path.isdir(abpath):
            targetindir = os.path.join(indir, os.path.splitext(rpath)[0])
            targetoutfile = os.path.join(outpath, rpath)
        import_asset(fpath, targetindir, targetoutfile, selects=selects, namestyle=namestyle)

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
    parser.add_argument("--namestyle", default="namethenpathid", help="namestyle for export and import", 
        choices=["uabea", "pathid", "seq", "namepathid", "nameseq", "namethenpathid"])
    parser.add_argument("--gameversion", default=None, help="specific unity version")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--gamedir", default=None, help="specific game root dir, should contains *_Data/Managed")
    group.add_argument("--dlldir", default=None, help="specific gamedll dir (including dummydll by il2cppdumper)")
    args = parser.parse_args(cmdstr.split(" ") if cmdstr else None)

    global GAME_DIR, GAME_VERSION, DLL_DIR
    GAME_DIR, DLL_DIR, GAME_VERSION = args.gamedir, args.dlldir, args.gameversion
    method, selects = args.method, args.selects
    searchpattern, namestyle = args.searchpattern, args.namestyle
    abpath, outpath, indir = args.abpath, args.outpath, args.indir
    if selects is not None: selects = selects.split(",")
    if method == "list":
        list_asset(abpath, outpath, selects=selects, searchpattern=searchpattern)
    elif method == "export":
        export_assert_multi(abpath, outpath, selects=selects, 
            searchpattern=searchpattern, namestyle=namestyle)
    elif method == "import":
        if indir is None: 
            raise ValueError(f"need to specific --indir (import dir)")
        import_asset_multi(abpath,indir, outpath, selects=selects, 
            searchpattern=searchpattern, namestyle=namestyle)
    else: raise ValueError(f"unknow operation {method}")

if __name__ == "__main__":
    cli()

"""
history
v0.1, initial version
v0.2, add MonoBehaviour and TextAsset
v0.2.1, add font
v0.2.2, add more options
v0.2.3, add specific unity version and managed dll, avoid same name export
v0.2.4, add namepatern for import and export
"""