/*
    win_redirect.js, by devseed, v0.1
    use this script to view and redirect something
    such as chcp codepage, replace font, replace path by pattern
*/

function chcp(codepage=-1, mute_log=false)
{
    const api = new ApiResolver("module"); 
    const MultiByteToWideChar  = new NativeFunction(
        api.enumerateMatches(
        'exports:*!MultiByteToWideChar')[0].address, 'int', ['uint', 'uint32','pointer', 'int', 'pointer','int']); 
    const WideCharToMultiByte  = new NativeFunction(
        api.enumerateMatches(
        'exports:*!WideCharToMultiByte')[0].address, 
        'int', ['uint', 'uint32', 'pointer', 
        'int', 'pointer', 'int', 'pointer', 'pointer']); 
    console.log('MultiByteToWideChar at'+ MultiByteToWideChar);
    console.log('WideCharToMultiByte at'+ WideCharToMultiByte);
    ;
    
    var lpMultiByteStr, lpWideCharStr;
    Interceptor.attach(MultiByteToWideChar, {
        onEnter: function (args, state) {
            if (codepage!=-1)
            {
                var codepage_before = args[0];
                args[0] = ptr(codepage);
                if(!mute_log)
                {
                    console.log("MultiByteToWideChar codepage",
                        codepage_before, ptr(codepage));
                }
            }
           lpMultiByteStr = args[2];
           lpWideCharStr = args[4];
        },
        onLeave: function (retval) {
            var ret_addr = "NOT_DETECTED"
            if(this.context.rsp!=undefined)
            {
                ret_addr = this.context.rsp.readPointer();
            }
            else if(this.context.esp!=undefined)
            {
                ret_addr = this.context.esp.readPointer();
            }

            if(!mute_log)
            {
                console.log(ret_addr.toString(16), 
                    "MultiByteToWideChar", retval, 
                    lpWideCharStr.readUtf16String());
            }
        }
    })

    Interceptor.attach(WideCharToMultiByte, {
        onEnter: function (args, state) {
            if (codepage!=-1)
            {
                var codepage_before = args[0];
                args[0] = ptr(codepage);
                if(!mute_log)
                {
                    console.log("MultiByteToWideChar codepage",
                        codepage_before, ptr(codepage));
                }
            }
           lpWideCharStr = args[2];
           lpMultiByteStr = args[4];
        },
        onLeave: function (retval) {
            var ret_addr = "NOT_DETECTED"
            if(this.context.rsp!=undefined)
            {
                ret_addr = this.context.rsp.readPointer();
            }
            else if(this.context.esp!=undefined)
            {
                ret_addr = this.context.esp.readPointer();
            }

            if(!mute_log)
            {
                console.log(ret_addr.toString(16), 
                    "WideCharToMultiByte", retval, 
                    lpWideCharStr.readUtf16String());
            }
        }
    })
}

function redirect_font(charset, facename, mute_log=false)
{
    const api = new ApiResolver("module"); 
    const CreateFontA  = new NativeFunction(
        api.enumerateMatches(
        'exports:*!CreateFontA')[0].address, 'pointer',
         ['int', 'int', 'int', 'int', 'int',
        'uint32', 'uint32','uint32','uint32',
        'uint32','uint32','uint32','uint32', 'pointer']); 
    const CreateFontW  = new NativeFunction(
        api.enumerateMatches(
        'exports:*!CreateFontW')[0].address, 'pointer',
            ['int', 'int', 'int', 'int', 'int',
        'uint32', 'uint32','uint32','uint32',
        'uint32','uint32','uint32','uint32', 'pointer']); 
    const CreateFontIndirectA  = new NativeFunction(
        api.enumerateMatches(
        'exports:*!CreateFontIndirectA')[0].address, 
        'pointer', ['pointer']); 
    const CreateFontIndirectW  = new NativeFunction(
        api.enumerateMatches(
        'exports:*!CreateFontIndirectW')[0].address, 
        'pointer', ['pointer']); 

    console.log('CreateFontA at'+ CreateFontA);
    console.log('CreateFontW at'+ CreateFontW);
    console.log('CreateFontIndirectA at'+ CreateFontIndirectA);
    console.log('CreateFontIndirectW at'+ CreateFontIndirectW);
    
    Interceptor.attach(CreateFontA, {
        onEnter: function(args)
        {
            var charset_before = args[8];
            var facename_before = args[13].readCString();
            args[13].writeAnsiString(facename);
            if(!mute_log)
            {
                console.log("CreateFontA charset", 
                    charset_before.toString(16), "->", 
                    charset.toString(16));
                console.log("CreateFontA facename", 
                    facename_before, "->", facename);
            }
        }
    })

    Interceptor.attach(CreateFontW, {
        onEnter: function(args)
        {
            var charset_before = args[8];
            var facename_before = args[13].readUtf16String();
            args[13].writeUtf16String(facename);
            if(!mute_log)
            {
                console.log("CreateFontW charset", 
                    charset_before.toString(16), "->", 
                    charset.toString(16));
                console.log("CreateFontW facename", 
                    facename_before, "->", facename);
            }
        }
    })


    Interceptor.attach(CreateFontIndirectA, {
        onEnter: function(args)
        {
            var lplf = args[0];
            
            var p = lplf.add(0x17);
            var charset_before = p.readU8();
            p.writeU8(charset);

            p = lplf.add(0x1c);
            var facename_before = p.readCString();
            p.writeAnsiString(facename);
            if(!mute_log)
            {
                console.log("CreateFontIndirectA charset", 
                    charset_before.toString(16), "->", 
                    charset.toString(16));
                console.log("CreateFontIndirectA facename", 
                    facename_before, "->", facename);
            }
        }
    })

    Interceptor.attach(CreateFontIndirectW, {
        onEnter: function(args)
        {
            var lplf = args[0];
            
            var p = lplf.add(0x17);
            var charset_before = p.readU8();
            p.writeU8(charset);

            p = lplf.add(0x1c);
            var facename_before = p.readUtf16String();
            p.writeUtf16String(facename);
            if(!mute_log)
            {
                console.log("CreateFontIndirectW charset", 
                    charset_before.toString(16), "->", 
                    charset.toString(16));
                console.log("CreateFontIndirectW facename", 
                    facename_before, "->", facename);
            }
        }
    })
}

function redirect_path(patterns, targets, mute_log=false)
{
    const api = new ApiResolver("module");
    const CreateFileA = new NativeFunction(
        api.enumerateMatches('exports:*!CreateFileA')[0].address, 'pointer', 
        ['pointer', 'uint32', 'uint32', 'pointer', 'uint32', 'uint32', 'uint32']); 
    const CreateFileW = new NativeFunction(
        api.enumerateMatches('exports:*!CreateFileW')[0].address, 'pointer', 
        ['pointer', 'uint32', 'uint32', 'pointer', 'uint32', 'uint32', 'uint32']); 
    
    var g_fargs = []
    Interceptor.attach(CreateFileW, {
        onEnter: function(args)
        {
            var filepath = args[0].readUtf16String();
            for(var i=0;i<patterns.length;i++)
            {
                var pattern = patterns[i];
                var target = targets[i];
                if (filepath.search(pattern)!=-1)
                {
                    filepath = filepath.replace(pattern, target)
                    args[0].writeUtf16String(filepath)
                }
            }
            g_fargs.push(filepath);
        },
        onLeave: function(retval)
        {
            
            var ret_addr = "NOT_DETECTED"
            if(this.context.rsp!=undefined)
            {
                ret_addr = this.context.rsp.readPointer();
            }
            else if(this.context.esp!=undefined)
            {
                ret_addr = this.context.esp.readPointer();
            }
            var filepath = g_fargs[0];
            if(retval.toInt32()!=0 && !mute_log)
            {
                console.log(ret_addr, "CreateFileW", filepath,"hFile=" + retval);
            }
            g_fargs = []
        }
    })
    Interceptor.attach(CreateFileA, {
        onEnter: function(args)
        {
            var filepath = args[0].readCString();
            for(var i=0;i<patterns.length;i++)
            {
                var pattern = patterns[i];
                var target = targets[i];
                if (filepath.search(pattern)!=-1)
                {
                    filepath = filepath.replace(pattern, target)
                    args[0].writeAnsiString(filepath)
                }
            }
            g_fargs.push(filepath);
        },
        onLeave: function(retval)
        {
            var ret_addr = "NOT_DETECTED"
            if(this.context.rsp!=undefined)
            {
                ret_addr = this.context.rsp.readPointer();
            }
            else if(this.context.esp!=undefined)
            {
                ret_addr = this.context.esp.readPointer();
            }
             
            var filepath = g_fargs[0];
            if(retval.toInt32()!=0 && !mute_log)
            {
                console.log(ret_addr,  "CreateFileA", 
                    filepath,"hFile=" + retval);
            }
            g_fargs = []
        }
    })
    
}

chcp(932, true); // cp932 sjis, cp936 gb2312
redirect_path([/patch(\d*)\.xp3/], ["patch$1_chs.xp3"], true);
redirect_font(0x80, "楷体", false);//0x80 sjis, 0x86 gb2312