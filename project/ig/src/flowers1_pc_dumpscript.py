import frida
import sys
"""
this is from flowers1 spring script1.dll, put that dll to other games plugin folders
sub_1001A340 //load script
1001A504 | 837C24 50 1 | cmp dword ptr ss:[esp + 50], 10          | [ebp+1ff4] text_buffer, esi length, [esp+3C] script name
1001A509 | 8BB5 F41F00 | mov esi, dword ptr ss:[ebp + 1FF4]       |
1001A50F | 89B5 F81F00 | mov dword ptr ss:[ebp + 1FF8], esi       | [ebp+1FF8]:"script/01a_00001.s"
1001A515 | 89B5 FC1F00 | mov dword ptr ss:[ebp + 1FFC], esi       |
1001A51B | 89B5 002000 | mov dword ptr ss:[ebp + 2000], esi       | [ebp+2000]:"script/01a_00001.s"
1001A521 | 72 0D       | jb script.1001A530 
"""

jscode = """
   'use strict';
   var g_null_count = 0;
   var scriptdll = Process.findModuleByName('Script.dll');
   var hook_script_offset = 0x1A504; 
   var load_script_offset = 0x1A340;
   var hook_script_ptr = scriptdll.base.add(hook_script_offset);
   var load_script_ptr = scriptdll.base.add(load_script_offset);

   // hook script method
   console.log(scriptdll.name, scriptdll.base);
   console.log("hooked text at ", hook_script_ptr);
   Interceptor.attach(hook_script_ptr, {
      onEnter: function (args) {
         console.log("In hook_text_offset");
         var script_addr = this.context.ebp.add(0x1FF4).readPointer();
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
   if len(sys.argv) < 2: process_name = "FLOWERS_CHS.exe"
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