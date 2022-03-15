"""
    modify windows pe with dll injected for hooking
    v0.2 developed by devseed

    history
    v0.1 injectdll by adding iat entry
    v0.2 use codecave to dynamiclly LoadLibraryA,
         to avoid windows defender assuming this as virus
"""

import sys
import os
import argparse
import lief
from keystone import Ks, KS_ARCH_X86, KS_MODE_32, KS_MODE_64

# This might be regared as virus by windows defender
# can not be ASLR
def injectdll_iat(exepath, dllpath, outpath="out.exe"): 
    binary_exe = lief.parse(exepath)
    binary_dll = lief.parse(dllpath)
    
    dllpath = os.path.basename(dllpath)
    dll_imp = binary_exe.add_library(dllpath)
    print("the import dll in " + exepath)
    for imp in binary_exe.imports:
        print(imp.name)

    for exp_func in binary_dll.exported_functions:
        dll_imp.add_entry(exp_func.name)
        print(dllpath + ", func "+ exp_func.name + " added!")

    # disable ASLR
    exe_oph =  binary_exe.optional_header
    exe_oph.remove(lief.PE.DLL_CHARACTERISTICS.DYNAMIC_BASE)

    builder = lief.PE.Builder(binary_exe)
    builder.build_imports(True).patch_imports(True)
    builder.build()
    builder.write(outpath)

# change the oep and use codecave for LoadLibrary dll
# only support for x86 and x64 architecture, no arm support
def injectdll_codecave(exepath, dllpath, outpath="out.exe"):
    # parsing pe
    pe = lief.parse(exepath)
    pe_oph = pe.optional_header
    imgbase = pe_oph.imagebase
    oeprva = pe_oph.addressof_entrypoint
    section_code = pe.section_from_rva(oeprva)
    impentry_LoadLibraryA = pe.get_import("KERNEL32.dll")\
            .get_entry("LoadLibraryA")

    # find position to code cave
    dllpath_bytes = dllpath.encode() + b'\x00'
    if pe_oph.magic == lief.PE.PE_TYPE.PE32_PLUS:
        print(f"{exepath}: oep={imgbase+oeprva:016X}, "
        f"code_section={imgbase+section_code.virtual_size:016X}, "
        f"LoadLibraryA={imgbase+impentry_LoadLibraryA.iat_address:016X}")
        max_len = len(dllpath_bytes) + 0x60
    elif pe_oph.magic == lief.PE.PE_TYPE.PE32:
        print(f"{exepath}: oep={imgbase+oeprva:08X}, "
        f"code_section={imgbase+section_code.virtual_size:08X}, "
        f"LoadLibraryA={imgbase+impentry_LoadLibraryA.iat_address:08X}")
        max_len = len(dllpath_bytes) + 0x20
    if section_code.sizeof_raw_data - section_code.virtual_size < max_len:
        print("error! can not find space for codecave")
        return 
    else:
        payload_rva = section_code.virtual_address + section_code.virtual_size

    # make code cave code
    if pe_oph.magic == lief.PE.PE_TYPE.PE32_PLUS:
        infostr = f"inject asm at {imgbase+payload_rva:016X}:"
        ks = Ks(KS_ARCH_X86, KS_MODE_64)
        code_str = f"""
            push rcx;
            lea rcx, [dllpath+1];
            mov rax, 0x{imgbase:016X};
            add rcx, rax;
            mov rax, 0x{imgbase+impentry_LoadLibraryA.iat_address:016X};
            call qword ptr ds:[rax];
            pop rcx;
            mov rax, 0x{imgbase+oeprva:016X};
            jmp rax; 
            dllpath:
            nop"""
        print(infostr, code_str)
        payload, _ = ks.asm(code_str, addr=payload_rva) # > 32bit error

    elif pe_oph.magic == lief.PE.PE_TYPE.PE32:
        infostr = f"try to inject asm at {imgbase+payload_rva:08X}:"
        ks = Ks(KS_ARCH_X86, KS_MODE_32)
        code_str = f"""
            pushad;
            mov eax, dllpath+1;
            push eax;
            call dword ptr ds:[0x{imgbase+impentry_LoadLibraryA.iat_address:08X}];
            popad;
            jmp 0x{imgbase+oeprva:08X};
            dllpath:
            nop"""
        print(infostr, code_str)
        payload, _ = ks.asm(code_str, addr=imgbase+payload_rva)
        
    else:
        print("error invalid pe magic!", pe_oph.magic)
        return

    payload = payload + list(dllpath_bytes)
    print("payload: ", [hex(x) for x in payload])

    # inject code
    section_code.virtual_size += len(payload)
    section_code.content += payload
    pe_oph.addressof_entrypoint = payload_rva
    pe_oph.remove(lief.PE.DLL_CHARACTERISTICS.DYNAMIC_BASE)
    builder = lief.PE.Builder(pe)
    builder.build()
    builder.write(outpath)

def debug():
    pass

def main():
    if len(sys.argv) < 3:
        print("injectdll exepath dllpath [-m|method iat|codecave(default)] [-o outpath]")
        return

    parser = argparse.ArgumentParser()
    parser.add_argument('exepath', type=str)
    parser.add_argument('dllpath', type=str)
    parser.add_argument('--method', '-m', default='codecave')
    parser.add_argument('--outpath', '-o', default='out.exe')
    args = parser.parse_args()
    if args.method.lower() == 'codecave':
        injectdll_codecave(args.exepath, args.dllpath, args.outpath)
    elif args.method.lower() == 'iat':
        injectdll_iat(args.exepath, args.dllpath, args.outpath)
    else:
        raise NotImplementedError()    
    
if __name__ == "__main__":
    #debug()
    main()
    pass