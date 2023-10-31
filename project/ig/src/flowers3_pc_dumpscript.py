import frida
import sys
"""
this is for flowers3 autumn, only the offset is changed.
sub_1001A2F0(int a1, void *a2)

.text:1001A4A0                 mov     ecx, [ebp+21DCh]
.text:1001A4A6                 mov     dl, [ecx+eax]
.text:1001A4A9                 add     ecx, eax
.text:1001A4AB                 inc     eax
.text:1001A4AC                 not     dl
.text:1001A4AE                 mov     [ecx], dl
.text:1001A4B0                 cmp     eax, esi
.text:1001A4B2                 jb      short loc_1001A4A0
.text:1001A4B4
.text:1001A4B4 loc_1001A4B4:                           ; CODE XREF: sub_1001A2F0+1AB↑j
.text:1001A4B4                 cmp     [esp+64h+var_14], 10h
.text:1001A4B9                 mov     esi, [ebp+21DCh]
.text:1001A4BF                 mov     [ebp+21E0h], esi
.text:1001A4C5                 mov     [ebp+21E4h], esi
.text:1001A4CB                 mov     [ebp+21E8h], esi
.text:1001A4D1                 jb      short loc_1001A4E0
.text:1001A4D3                 mov     eax, [esp+64h+Src]
.text:1001A4D7                 push    eax             ; void *
.text:1001A4D8                 call    ??3@YAXPAX@Z    ; operator delete(void *)
.text:1001A4DD                 add     esp, 4
"""

jscode = """
   'use strict';
   var g_null_count = 0;
   var scriptdll = Process.findModuleByName('Script.dll');
   var hook_script_offset = 0x1A4B4; 
   var load_script_offset = 0x1A2F0;
   var hook_script_ptr = scriptdll.base.add(hook_script_offset);
   var load_script_ptr = scriptdll.base.add(load_script_offset);

   // hook script method
   console.log(scriptdll.name, scriptdll.base);
   console.log("hooked text at ", hook_script_ptr);
   Interceptor.attach(hook_script_ptr, {
      onEnter: function (args) {
         console.log("In hook_text_offset");
         var script_addr = this.context.ebp.add(0x21DC).readPointer();
         var script_length = this.context.esi.toInt32();
         var script_data = script_addr.readByteArray(script_length);
         var name = "null";
         try {  
            var name_addr = this.context.esp.add(0x3C).readPointer();
            name = name_addr.readCString();
            name = name.split('/')[name.split('/').length - 1];
         }
         catch (e) {
            console.log(e.message);
            name = "null" + g_null_count.toString() + ".s";
            g_null_count++;
         }
         console.log(name, "script_addr:", script_addr, "length:", script_length);
        
         var file = new File(name, "wb");
         file.write(script_data);
         file.close();
      }
   })
   
   // to decrypt scripts
   var g_buf = Memory.alloc(0x10000);
   var g_buf_name = Memory.alloc(256);
   var load_script = new NativeFunction(load_script_ptr, 'void', ['pointer', 'pointer'], 'fastcall');
   console.log("load_script_func at:", load_script_ptr)
   
   var op = recv('filelist', function(v){ 
      var filelist = v.payload;
      for (var i in filelist){
         console.log(i, filelist[i], "to be dumped...")
         g_buf_name.writeAnsiString(filelist[i]);
         load_script(g_buf, g_buf_name);
      }
   });
  """ 

def on_message(message, data):
    print(message, data)

def main():
   print("dump_flowers_script [flowers_exepath] [filelistpath]")
   filelist = []
   if len(sys.argv) < 2: process_name = "FLOWERS3_CHS.exe"
   else: process_name = sys.argv[1]
   if len(sys.argv) >= 3: 
      with open(sys.argv[2], 'r') as fp:
         for line in fp.readlines():
             filelist.append(line.strip('\n').strip('\r'))

   session = frida.attach(process_name)
   script = session.create_script(jscode)
   script.on('message', on_message)
   script.load()
   script.post({'type':'filelist', 'payload':filelist})
   sys.stdin.read()

if __name__ == "__main__":
   main()