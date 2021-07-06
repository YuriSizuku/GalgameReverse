import lief
import sys
import os

def injectdll(exepath, dllpath, outpath="out.exe"): # can not be ASLR
    binary_exe = lief.parse(exepath)
    binary_dll = lief.parse(dllpath)
    
    dllname = os.path.basename(dllpath)
    dll_imp = binary_exe.add_library(dllname)
    print("the import dll in " + exepath)
    for imp in binary_exe.imports:
        print(imp.name)

    for exp_func in binary_dll.exported_functions:
        dll_imp.add_entry(exp_func.name)
        print(dllname + ", func "+ exp_func.name + " added!")

    # disable ASLR
    exe_oph =  binary_exe.optional_header;
    exe_oph.remove(lief.PE.DLL_CHARACTERISTICS.DYNAMIC_BASE)

    builder = lief.PE.Builder(binary_exe)
    builder.build_imports(True).patch_imports(True)
    builder.build()
    builder.write(outpath)

def main():
    if len(sys.argv) < 3:
        print("injectdll exepath dllpath [outpath]")
        return
    outpath = "out.exe" if len(sys.argv) < 4 else sys.argv[3]
    injectdll(sys.argv[1], sys.argv[2], outpath)
    
if __name__ == "__main__":
    main()