import frida
import sys
"""
this is for flowers2 summer, only the offset is changed.
sub_10019EE0(int a1, void *a2)

1001A0A2 | 72 EC       | jb script.1001A090                       |
1001A0A4 | 837C24 50 1 | cmp dword ptr ss:[esp + 50], 10          |
1001A0A9 | 8BB5 D82100 | mov esi, dword ptr ss:[ebp + 21D8]       | [ebp + 21d8]  is the buffer
1001A0AF | 89B5 DC2100 | mov dword ptr ss:[ebp + 21DC], esi       | 
1001A0B5 | 89B5 E02100 | mov dword ptr ss:[ebp + 21E0], esi       |
1001A0BB | 89B5 E42100 | mov dword ptr ss:[ebp + 21E4], esi       |
1001A0C1 | 72 0D       | jb script.1001A0D0                       |
1001A0C3 | 8B4424 3C   | mov eax, dword ptr ss:[esp + 3C]         | [esp+3C]:"script/02a_00001.s"

"""

jscode = """
   'use strict';
   var g_null_count = 0;
   var scriptdll = Process.findModuleByName('Script.dll');
   var hook_script_offset = 0x1A0A4; 
   var load_script_offset = 0x19EE0;
   var hook_script_ptr = scriptdll.base.add(hook_script_offset);
   var load_script_ptr = scriptdll.base.add(load_script_offset);

   // hook script method
   console.log(scriptdll.name, scriptdll.base);
   console.log("hooked text at ", hook_script_ptr);
   Interceptor.attach(hook_script_ptr, {
      onEnter: function (args) {
         console.log("In hook_text_offset");
         var script_addr = this.context.ebp.add(0x21D8).readPointer();
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
   if len(sys.argv) < 2: process_name = "FLOWERS2_CHS.exe"
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