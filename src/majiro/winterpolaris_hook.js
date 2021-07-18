var g_base =  0x400000; 

function hook_fopen_fread() // print fopen and fread to investigate file structor
{
    var memove = new NativeFunction(ptr(g_base + 0x8aa80), 
        'void', ["pointer", "pointer", "int"]);
    var sprintf = new NativeFunction(ptr(g_base + 0x89493), 
        'int', ["pointer", "pointer", "..."], "mscdecl");
    var fopen = new NativeFunction(ptr(g_base + 0x88F86), 
        'pointer', ["pointer", "pointer"]); // in this game, all file function is static link
    var fread = new NativeFunction(ptr(g_base + 0x8B609), 
        'size_t', ['pointer', 'size_t', 'size_t', 'size_t']);
    var fseek = new NativeFunction(ptr(g_base + 0x8DAD2), 
        'int', ["pointer", "int", "int"]);
    var ftell = new NativeFunction(ptr(g_base + 0x8EEF6), 
        'int', ["pointer"]);
    var g_fargs = [];
    Interceptor.attach(fopen, {
        onEnter: function(args)
        {
            g_fargs.push(args[0].readCString());
        },
        onLeave: function(retval)
        {
            var ret_addr = this.context.esp.readPointer();
            var filepath = g_fargs[0];
            if(retval.toInt32()!=0)
            {
                console.log(ret_addr, 
                    "fopen", 
                    filepath.split('\\')[filepath.split('\\').length-1],
                    "fp=" + retval);
            }
            g_fargs = []
        }
    })
    Interceptor.attach(fread, {
        onEnter: function(args)
        {
            var ret_addr = this.context.esp.readPointer();
            var fp = args[3];
            var offset = ftell(fp);
            console.log(ret_addr, 
                "fread(" + args[0]+", " + args[1]+", " + args[2] + ", " + fp + ")", 
                "offset=0x" + offset.toString(16));
        }
    })
}

function hook_showtext() //  for investigating the text structure(offset and content) and  substitude text
{
   /* 
    0043A750  | 8B15 581A5D00                 | mov edx,dword ptr ds:[5D1A58]      | edx:&"1"
    0043A756  | 8B0A                          | mov ecx,dword ptr ds:[edx]         | [edx]:"1"
    0043A758  | 0FBF01                        | movsx eax,word ptr ds:[ecx]        | get_text_len
    0043A75B  | 83C1 02                       | add ecx,2                          | move to text
    0043A75E  | 890A                          | mov dword ptr ds:[edx],ecx         | [edx]:"1"
    0043A760  | C3                            | ret                                |
   
    00445BA0  | C780 E8D05200 01000000        | mov dword ptr ds:[eax+52D0E8],1    |
    00445BAA  | 8D80 E8CC5200                 | lea eax,dword ptr ds:[eax+52CCE8]  | eax:L"簀簀簀簀簀簀簀簀簀"
    00445BB0  | 8B35 581A5D00                 | mov esi,dword ptr ds:[5D1A58]      | 5D1A58, mjo decrypt text
    00445BB6  | 53                            | push ebx                           | size
    00445BB7  | A3 E4CC5200                   | mov dword ptr ds:[52CCE4],eax      | write 52cce4
    00445BBC  | FF36                          | push dword ptr ds:[esi]            | src: [esi] mjo decrypt text
    00445BBE  | 50                            | push eax                           | dst: 52cce4, show test, not all text go 00445BBE
    00445BBF  | E8 BC4E0400                   | call <polaris_chs.sub_48AA80>      | */

    Interceptor.attach(ptr(g_base+ 0x42820), {
        onEnter: function(args)
        {
            var mjo_struct = ptr(g_base + 0XDC350).readPointer();
            var mjo_name = mjo_struct.readAnsiString();
            var mjo_addr_base = mjo_struct.add(0x29*4).readPointer();
            var mjo_addr_cur = ptr(g_base + 0x5D1A58 - 0x400000).readPointer().readPointer();

            // because point at 4208, go to the start of str buf addr
            while(mjo_addr_cur.readU8()!=0) mjo_addr_cur=mjo_addr_cur.sub(1); 
            mjo_addr_cur=mjo_addr_cur.sub(1)
            while(mjo_addr_cur.readU8()!=0) mjo_addr_cur=mjo_addr_cur.sub(1); 
            mjo_addr_cur=mjo_addr_cur.add(1);
            
            var text_addr = ptr(g_base + 0x52CCE4 - 0x400000).readPointer(); // you can replace your own text here
            var text = text_addr.readAnsiString();
            //text_addr.writeAnsiString("+0x"+(mjo_addr_cur - mjo_addr_base).toString(16));
            console.log(mjo_name, mjo_addr_base, "+0x"+(mjo_addr_cur - mjo_addr_base).toString(16), text);
        },
    });
}

function chcp936(fontname="simhei")
{
    const api = new ApiResolver("module");
    const CreateFontIndirectA = new NativeFunction(api.enumerateMatches("exports:*!CreateFontIndirectA")[0].address, "pointer", ["pointer"], "stdcall")
    console.log("CreateFontIndirectA at", CreateFontIndirectA);
    Interceptor.attach(CreateFontIndirectA, {
        onEnter: (args)=>
        {
            ptr(args[0]).add(0x17).writeU8(0x86);
            ptr(args[0]).add(0x1c).writeAnsiString(fontname);
        }
    })
}

function dump_mjo(mjo_name, dump_dir="./dump/") // to dump decrypted mjo
{
    /*
    ...
      if ( strlen(mjo_Filename) > 0x7F )
    sub_441150(
      "ファイル名[%s]が長すぎます%d文字以内にしてください。",
      (int)mjo_Filename,
      127,
      (int)FullPath,
      v28);
      ...    
    if ( v29 )
    sub_478E70(*((__m128i **)context + 0x29), *((_DWORD *)context + 0x24));// decrypt mjo, dword 0x24 is context+0x90
    v19 = mjo_Filename;
    */
    
    // better to attach process, after initial, or access violation
    var decrypt_func = new NativeFunction(ptr(g_base + 0x40AB0),
        'pointer', ['pointer'], 'stdcall');
    var name_buf = Memory.alloc(256).writeAnsiString(mjo_name);
    var decrypt_ret = decrypt_func(name_buf);
    let mjo_size = decrypt_ret.add(0x24*4).readU32();
    let mjo_buf  = decrypt_ret.add(0x29*4).readPointer();
    console.log(mjo_name, mjo_buf, mjo_size);
    var fp = new File(dump_dir + mjo_name, "wb");
    fp.write(mjo_buf.readByteArray(mjo_size));
    fp.close()
}

function dump_mjo_all(dump_dir="./dump/")
{
    var name_list = ["a01.mjo",
    "a02.mjo",
    "a03.mjo",
    "a04.mjo",
    "a05.mjo",
    "a06.mjo",
    "a07.mjo",
    "a08.mjo",
    "a09.mjo",
    "a10.mjo",
    "b01.mjo",
    "b02.mjo",
    "b03.mjo",
    "b04.mjo",
    "b05.mjo",
    "b06.mjo",
    "b07.mjo",
    "b08.mjo",
    "boss.mjo",
    "buttonmenu.mjo",
    "cgmode.mjo",
    "config.mjo",
    "console.mjo",
    "epilogue.mjo",
    "gaizi.mjo",
    "help.mjo",
    "history.mjo",
    "kosihata.mjo",
    "load_sysdata.mjo",
    "loadsave.mjo",
    "menu.mjo",
    "message_box.mjo",
    "music.mjo",
    "pausemenu.mjo",
    "pic.mjo",
    "staffroom.mjo",
    "start.mjo",
    "sub_title.mjo",
    "transit.mjo",
    "transit_top.mjo",
    "usertrans.mjo",
    "yazlib.mjo",];
    for(let i=0;i<name_list.length;i++)
    {
        dump_mjo(name_list[i], dump_dir);
    }
}

//hook_fopen_fread()
chcp936();
hook_showtext();
//dump_mjo_all()