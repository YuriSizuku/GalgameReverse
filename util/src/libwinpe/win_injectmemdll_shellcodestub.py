"""
   this file is for automaticly generate some shellcodes stub informations
   v0.1, developed by devseed
"""
import re
import sys
import lief
from keystone import Ks, KS_ARCH_X86, KS_MODE_32, KS_MODE_64

def gen_oepshellcode32():
   ks = Ks(KS_ARCH_X86, KS_MODE_32)
   code_str = f"""
      // for relative address, get the base of addr
      call geteip; 
      lea ebx, [eax-5];

      // bind iat
      lea eax, [ebx + exegetprocessaddress];
      mov eax, [eax]; // iat
      mov eax, [eax]; // iat->addr
      push eax; 
      lea eax, [ebx + exeloadlibrarya];
      mov eax, [eax]; // iat
      mov eax, [eax]; // iat->addr
      push eax;
      lea eax, [ebx + dllbase]; // dllbase addr
      mov eax, [eax]; // dllbase value
      push eax;
      call [ebx + memiatbind];
      add esp, 0xC;
      
      // call dll oep, for dll entry
      xor eax, eax; 
      push eax; // lpvReserved
      inc eax;
      push eax; // fdwReason, DLL_PROCESS_ATTACH
      lea eax, [ebx + dllbase];
      mov eax, [eax];
      push eax; // hinstDLL
      call [ebx+dlloepva];

      // jmp to origin oep
      jmp [ebx+exeoepva];

      geteip:
      mov eax, [esp]
      ret

      exeoepva: nop;nop;nop;nop;
      dllbase: nop;nop;nop;nop;
      dlloepva: nop;nop;nop;nop;
      memiatbind: nop;nop;nop;nop;
      exeloadlibrarya: nop;nop;nop;nop;
      exegetprocessaddress: nop;nop;nop;nop;
      """
   print("gen_oepshellcode32", code_str)
   payload, _ = ks.asm(code_str)
   print("payload: ", [hex(x) for x in payload])
   return payload

def gen_oepshellcode64():
   ks = Ks(KS_ARCH_X86, KS_MODE_64)
   pass

def inject_shellcodestubs(srcpath, libwinpepath, targetpath):
   pedll = lief.parse(libwinpepath)
   pedll_oph = pedll.optional_header
   memiatfunc = next(filter(
      lambda e : e.name == "winpe_membindiat", 
      pedll.exported_functions))
   memiatshellcode = \
      pedll.get_content_from_virtual_address(
         memiatfunc.address, 0x200)
   memiatshellcode = memiatshellcode[:memiatshellcode.index(0xC3)+1] # retn

   if pedll_oph.magic == lief.PE.PE_TYPE.PE32_PLUS:
      oepshellcode = gen_oepshellcode64()
      pass
   elif pedll_oph.magic == lief.PE.PE_TYPE.PE32:
      oepshellcode = gen_oepshellcode32()
      pass
   else:
      print("error invalid pe magic!", pedll_oph.magic)
      return

   with open(srcpath, "rb") as fp:
      srctext = fp.read().decode('utf8')

   _codetext = ",".join([hex(x) for x in oepshellcode])
   srctext = re.sub(r"g_oepshellcode(.+?)(\{0x90\})", 
      r"g_oepshellcode\1{" + _codetext +"}", srctext)
   _codetext = ",".join([hex(x) for x in memiatshellcode])
   srctext = re.sub(r"g_memiatshellcode(.+?)(\{0x90\})", 
      r"g_memiatshellcode\1{" + _codetext +"}", srctext)

   with open(targetpath, "wb") as fp:
      fp.write(srctext.encode('utf8'))

def debug():
   inject_shellcodestubs("win_injectmemdll.c", 
      "./../../bin/libwinpe32.dll", 
      "./../../bin/_win_injectmemdll.c")
   pass

def main():
   if len(sys.argv) < 4:
      print("win_injectmemdll_shellcodestub srcpath libwinpedllpath outpath")
      return
   inject_shellcodestubs(sys.argv[1], 
      sys.argv[2].replace("d.dll", ".dll"), sys.argv[3])
   pass

if __name__ == "__main__":
   debug()
   main()
   pass