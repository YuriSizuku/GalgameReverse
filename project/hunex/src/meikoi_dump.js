/**
 * An experiment for invoking il2cpp function
 * to dump script_dialog_xx.hdlg in 明治東亰恋伽
 *   v0.1, devloped by devseed
 * 
 *  usage:
 *    npm i  @types/frida-gum --save
 *    frida -l meikoi_hook.js -f meikoi.exe
 * 
 */

/**
 * print memo dump with asci
 * @param {NativePointer} mem 
 * @param {number} size 
 */
function print_mem(mem, size=256) {
    console.log(hexdump(mem, {offset: 0, length: size, header: true, ansi: true}));
}

/**
 *  convert il2str to js str
 * @param {NativePointer} mem 
 */
function il2str(mem, str=null) {
    // struct System_String_o {
    //     System_String_c* klass;
    //     void* monitor;
    //     System_String_Fields fields;
    // };
    // struct __declspec(align(8)) System_String_Fields {
    //     int32_t _stringLength;
    //     uint16_t _firstChar;
    // };
    var oldstr = mem.add(0x10+0x4).readUtf16String();
    if(str) {
        mem.add(0x10).writeU32(str.length);
        mem.add(0x10+0x4).writeUtf16String(str);
    }
    return oldstr;
}

/**
 * convert il2 bytes to js bytes array
 * @param {NativePointer} mem 
 */
function il2bytes(mem) {
    // struct Il2CppObject
    // {
    //     Il2CppClass *klass;
    //     void *monitor;
    // };
    // struct Il2CppArrayBounds
    // {
    //     il2cpp_array_size_t length;
    //     il2cpp_array_lower_bound_t lower_bound;
    // };
    // struct System_Byte_array {
    //     Il2CppObject obj;
    //     Il2CppArrayBounds *bounds;
    //     il2cpp_array_size_t max_length;
    //     uint8_t m_Items[65535];
    // };
    var bounds = mem.add(0x10).readPointer();
    var length = mem.add(0x18).readU64();
    if (bounds > 0)
    {
        length = bounds.readU64();
    }
    var m_Items = mem.add(0x20);
    return m_Items.readByteArray(length);
}

/**
 * binding the il2 functions
 */
function get_il2() {
    var il2 = {};
    var module = Module.load("GameAssembly.dll");
    il2.module = module;
    var func = {};
    il2.func = func;
    console.log(`load ${module.path} at ${module.base.toString()}`);
    
    // [Token(Token = "0x6000CEA")]
    // [Address(RVA = "0x648190", Offset = "0x647190", VA = "0x180648190")]
    // public unas_BinaryRead()
    // void __stdcall hunex_UNAS_Systems_Files_unas_BinaryRead___ctor(
    //     hunex_UNAS_Systems_Files_unas_BinaryRead_o *this,
    //     const MethodInfo *method)
    func.hunex_UNAS_Systems_Files_unas_BinaryRead___ctor = new NativeFunction(
        module.base.add(0x648190),"void", ["pointer", "pointer"]);
    
    // [Token(Token = "0x6000CF2")]
    // [Address(RVA = "0x648420", Offset = "0x647420", VA = "0x180648420")]
    // public void Read(string path, long offset, long length)
    // void __stdcall hunex_UNAS_Systems_Files_unas_BinaryRead__Read(
    //     hunex_UNAS_Systems_Files_unas_BinaryRead_o *this,
    //     System_String_o *path,
    //     int64_t offset,
    //     int64_t length,
    //     const MethodInfo *method)
    func.hunex_UNAS_Systems_Files_unas_BinaryRead__Read = new NativeFunction(
        module.base.add(0x648420), "void", ["pointer", "pointer", "int64", "int64", "pointer"]);
    
    // [Token(Token = "0x6000CF5")] 
    // [Address(RVA = "0x648940", Offset = "0x647940", VA = "0x180648940")]
    // private UniTask<byte[]> binaryRead(string path, long offset, long length, CancellationToken ct)
    // Cysharp_Threading_Tasks_UniTask_byte____o *hunex_UNAS_Systems_Files_unas_BinaryRead__binaryRead(
    //     Cysharp_Threading_Tasks_UniTask_byte____o *retstr,
    //     hunex_UNAS_Systems_Files_unas_BinaryRead_o *this,
    //     System_String_o *path,
    //     int64_t offset,
    //     int64_t length,
    //     System_Threading_CancellationToken_o ct,
    //     const MethodInfo *method)
    func.hunex_UNAS_Systems_Files_unas_BinaryRead__binaryRead = module.base.add(0x648940);
    
    // [Token(Token = "0x6001C85")]
    // [Address(RVA = "0x48F860", Offset = "0x48E860", VA = "0x18048F860")]
    // public UniTask LoadLanguage(string langName)
    // Cysharp_Threading_Tasks_UniTask_o *hunex_UNAS_ADV_Script_unas_ScriptLoader__LoadLanguage(
    //     Cysharp_Threading_Tasks_UniTask_o *retstr,
    //     hunex_UNAS_ADV_Script_unas_ScriptLoader_o *this,
    //     System_String_o *langName,
    //     const MethodInfo *method)
    func.hunex_UNAS_ADV_Script_unas_ScriptLoader__LoadLanguage = module.base.add(0x48F860)


    // [Token(Token = "0x6001C83")]
    // [Address(RVA = "0x48F630", Offset = "0x48E630", VA = "0x18048F630")]
    // public string GetDialog(int no)
    // System_String_o *__stdcall hunex_UNAS_ADV_Script_unas_ScriptLoader__GetDialog(
    //         hunex_UNAS_ADV_Script_unas_ScriptLoader_o *this,
    //         int32_t no,
    //         const MethodInfo *method)
    func.hunex_UNAS_ADV_Script_unas_ScriptLoader__GetDialog = module.base.add(0x48F630)

    // [Token(Token = "0x6001C7E")]
    // [Address(RVA = "0x48F010", Offset = "0x48E010", VA = "0x18048F010")]
    // public byte[] GetScriptNo(int no, ref string name)
    // System_Byte_array *__stdcall hunex_UNAS_ADV_Script_unas_ScriptLoader__GetScriptNo(
    //         hunex_UNAS_ADV_Script_unas_ScriptLoader_o *this,
    //         int32_t no,
    //         System_String_o **name,
    //         const MethodInfo *method)
    func.hunex_UNAS_ADV_Script_unas_ScriptLoader__GetScriptNo = module.base.add(0x48F010)

    return il2;
}

/**
 * log class, hunex.UNAS.Systems.Files.unas_BinaryRead 
 */ 
function log_unas_BinaryRead(il2_func) {
    Interceptor.attach(il2_func.hunex_UNAS_Systems_Files_unas_BinaryRead___ctor, {
        onEnter: function(args)
        {
            //console.log(`[unas_BinaryRead] this=${args[0].toString()} method=${args[1].toString()}`);
        },
        onLeave: function(args)
        {
        }
    })

    Interceptor.attach(il2_func.hunex_UNAS_Systems_Files_unas_BinaryRead__Read, {
        onEnter: function(args)
        {
            let path = il2str(args[1])
            let offset = args[2];
            let length = args[3];
            console.log(`[unas_BinaryRead.Read] path=${path} `+
                            `offset=${offset.toString(16)} length=${length.toString(16)}`);
        }, onLeave: function(ret)
        {
            
        }
    })

    // data.hpb. adv.hpb, script.heslnk, script_dialog_zhcn.hdlg
    Interceptor.attach(il2_func.hunex_UNAS_Systems_Files_unas_BinaryRead__binaryRead, {
        onEnter: function(args)
        {
            let path = il2str(args[2])
            let offset = args[3];
            let length = args[4];
            console.log(`[unas_BinaryRead.binaryRead] path=${path} ` + 
                            `offset=0x${offset.toString(16)} length=0x${length.toString(16)}`);
        }, onLeave: function(ret)
        {
            
        }
    })
}

/**
 * log class, hunex.UNAS.ADV.Script.unas_ScriptLoader
 */
function log_unas_ScriptLoader(il2_func) {
    Interceptor.attach(il2_func.hunex_UNAS_ADV_Script_unas_ScriptLoader__LoadLanguage, {
        onEnter: function(args)
        {
            var lang = il2str(args[2]);
            console.log(`[unas_ScriptLoader.LoadLanguage] lang=${lang}`);
        },
        onLeave: function(ret)
        {
        }
    });

    Interceptor.attach(il2_func.hunex_UNAS_ADV_Script_unas_ScriptLoader__GetDialog, {
        onEnter: function(args)
        {
            var no = args[1].readU32();
            console.log(`[unas_ScriptLoader.GetDialog] no=${no}`);
        },
        onLeave: function(ret)
        {
        }
    });

    Interceptor.attach(il2_func.hunex_UNAS_ADV_Script_unas_ScriptLoader__GetScriptNo, {
        onEnter: function(args)
        {
            var no = args[1].readU32();
            console.log(`[unas_ScriptLoader.GetScriptNo] no=${no}`);
        },
        onLeave: function(ret)
        {
        }
    });
}


function dump_script_dialog(il2_func, outpath=null, lang=null)
{
    var ScriptLoader_obj = null;
    var dump_finish =false;
    Interceptor.attach(il2_func.hunex_UNAS_ADV_Script_unas_ScriptLoader__LoadLanguage, {
        onEnter: function(args) {
            ScriptLoader_obj = args[1];
            if(!lang) lang = il2str(args[2]);
            else il2str(args[2], lang);
            console.log(`[dump_script_dialog before] lang=${lang}`);
        }
    });

    Interceptor.attach(il2_func.hunex_UNAS_Systems_Files_unas_BinaryRead__binaryRead, {
        onEnter: function(args) {
            if(!ScriptLoader_obj || dump_finish) return;
            var fields = ScriptLoader_obj.add(0x10);
            var m_busy = fields.add(0x8*9).readS32();
            var m_language = fields.add(0x18).readPointer();
            if(!m_busy && m_language > 0)
            {
                dump_finish = true;
                var m_scriptPath = il2str(fields.add(0x8*7).readPointer());
                var m_langPath = il2str(fields.add(0x8*8).readPointer());
                var lang_data = il2bytes(m_language);
                if(!outpath) outpath = m_langPath + ".dump";
                File.writeAllBytes(outpath, lang_data)
                console.log(`[dump_script_dialog after] ${lang_data.length} bytes saved at ${outpath}`);
            }
        }
    });
}

var g_il2 = get_il2();
// log_unas_BinaryRead(g_il2.func);
// log_unas_ScriptLoader(g_il2.func)
// dump_script_dialog(g_il2.func, "./meikoi_Data/StreamingAssets/script/script_dialog_en.dump", "./meikoi_Data/StreamingAssets/script/script_dialog_en.hdlg")
// dump_script_dialog(g_il2.func, "./meikoi_Data/StreamingAssets/script/script_dialog_ja.dump", "./meikoi_Data/StreamingAssets/script/script_dialog_ja.hdlg")
dump_script_dialog(g_il2.func)