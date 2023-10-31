import frida
import sys

"""
this is for flowers4 winter (steam chs version), only the offset is changed.
## steam

sub_1001DAD0(int a1, void *a2) // search CreateStream for location

.text:1001DC80                   loc_1001DC80: 
.text:1001DC80 8B 8D E0 21 00 00                 mov     ecx, [ebp+21E0h]
.text:1001DC86 8A 14 01                          mov     dl, [ecx+eax]
.text:1001DC89 03 C8                             add     ecx, eax
.text:1001DC8B 40                                inc     eax
.text:1001DC8C F6 D2                             not     dl
.text:1001DC8E 88 11                             mov     [ecx], dl
.text:1001DC90 3B C6                             cmp     eax, esi
.text:1001DC92 72 EC                             jb      short loc_1001DC80
.text:1001DC94
.text:1001DC94      loc_1001DC94:               
.text:1001DC94 83 7C 24 50 10                    cmp     [esp+64h+var_14], 10h
.text:1001DC99 8B B5 E0 21 00 00                 mov     esi, [ebp+21E0h]
.text:1001DC9F 89 B5 E4 21 00 00                 mov     [ebp+21E4h], esi
.text:1001DCA5 89 B5 E8 21 00 00                 mov     [ebp+21E8h], esi
.text:1001DCAB 89 B5 EC 21 00 00                 mov     [ebp+21ECh], esi
.text:1001DCB1 72 0D                             jb      short loc_1001DCC0
.text:1001DCB3 8B 44 24 3C                       mov     eax, [esp+64h+Source]
.text:1001DCB7 50                                push    eax             ; void *
.text:1001DCB8 E8 01 3E 03 00                    call    ??3@YAXPAX@Z    ; operator delete(void *)
.text:1001DCBD 83 C4 04                          add     esp, 4
"""

jscode_steam = """
   'use strict';
   var g_null_count = 0;
   var scriptdll = Process.findModuleByName('Script.dll');
   var hook_script_offset = 0x1DC94; 
   var load_script_offset = 0x1DAD0;
   var hook_script_ptr = scriptdll.base.add(hook_script_offset);
   var load_script_ptr = scriptdll.base.add(load_script_offset);

   // hook script method
   console.log(scriptdll.name, scriptdll.base);
   console.log("hooked text at ", hook_script_ptr);
   Interceptor.attach(hook_script_ptr, {
      onEnter: function (args) {
         console.log("In hook_text_offset");
         var script_addr = this.context.ebp.add(0x21E0).readPointer();
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

"""
## pkg 
sub_1001D660(int a1, void *a2)

.text:1001D810 loc_1001D810:                           ; CODE XREF: sub_1001D660+1C2↓j
.text:1001D810                 mov     ecx, [ebp+21E0h]
.text:1001D816                 mov     dl, [ecx+eax]
.text:1001D819                 add     ecx, eax
.text:1001D81B                 inc     eax
.text:1001D81C                 not     dl
.text:1001D81E                 mov     [ecx], dl
.text:1001D820                 cmp     eax, esi
.text:1001D822                 jb      short loc_1001D810
.text:1001D824
.text:1001D824 loc_1001D824:                           ; CODE XREF: sub_1001D660+1AB↑j
.text:1001D824                 cmp     [esp+64h+var_14], 10h
.text:1001D829                 mov     esi, [ebp+21E0h]
.text:1001D82F                 mov     [ebp+21E4h], esi
.text:1001D835                 mov     [ebp+21E8h], esi
.text:1001D83B                 mov     [ebp+21ECh], esi
.text:1001D841                 jb      short loc_1001D850
.text:1001D843                 mov     eax, [esp+64h+Src]
.text:1001D847                 push    eax             ; void *
.text:1001D848                 call    ??3@YAXPAX@Z    ; operator delete(void *)
.text:1001D84D                 add     esp, 4
"""
jscode_pkg = """
   'use strict';
   var g_null_count = 0;
   var scriptdll = Process.findModuleByName('Script.dll');
   var hook_script_offset = 0x1D824; 
   var load_script_offset = 0x1D660;
   var hook_script_ptr = scriptdll.base.add(hook_script_offset);
   var load_script_ptr = scriptdll.base.add(load_script_offset);

   // hook script method
   console.log(scriptdll.name, scriptdll.base);
   console.log("hooked text at ", hook_script_ptr);
   Interceptor.attach(hook_script_ptr, {
      onEnter: function (args) {
         console.log("In hook_text_offset");
         var script_addr = this.context.ebp.add(0x21E0).readPointer();
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
   if len(sys.argv) < 2: process_name = "FLOWERS4_CHS.exe"
   else: process_name = sys.argv[1]
   if len(sys.argv) >= 3: 
      with open(sys.argv[2], 'r') as fp:
         for line in fp.readlines():
             filelist.append(line.strip('\n').strip('\r'))

   session = frida.attach(process_name)
   script = session.create_script(jscode_steam)
   script.on('message', on_message)
   script.load()
   script.post({'type':'filelist', 'payload':filelist})
   sys.stdin.read()

if __name__ == "__main__":
   main()