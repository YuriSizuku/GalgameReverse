/*
    win_file.js, by devseed, v0.1
    use this script to log the windows file api function
*/

function hook_cfile(idx=0)
{
    const api = new ApiResolver("module");
    const fopen = new NativeFunction(
        api.enumerateMatches('exports:*!fopen')[idx].address, 
        'pointer', ['pointer', 'pointer']);
    const fclose = new NativeFunction(
        api.enumerateMatches('exports:*!fclose')[idx].address, 
        'int', ['pointer']);
    const fseek = new NativeFunction( 
        api.enumerateMatches('exports:*!fseek')[idx].address, 
        'int', ['pointer', 'size_t', 'int']);
    const ftell = new NativeFunction( 
        api.enumerateMatches('exports:*!ftell')[idx].address, 
        'size_t', ['pointer']);
    const fread = new NativeFunction( 
        api.enumerateMatches('exports:*!fread')[idx].address,  
        'size_t', ['pointer', 'size_t', 'size_t', 'pointer']);
    const fwrite = new NativeFunction( 
        api.enumerateMatches('exports:*!fwrite')[idx].address, 
        'size_t', ['pointer', 'size_t', 'size_t', 'pointer']);

    console.log(api.enumerateMatches('exports:*!fopen')[idx].name ,fopen);
    console.log(api.enumerateMatches('exports:*!fclose')[idx].name, fclose);
    console.log(api.enumerateMatches('exports:*!ftell')[idx].name, ftell);
    console.log(api.enumerateMatches('exports:*!fseek')[idx].name, fseek);
    console.log(api.enumerateMatches('exports:*!fread')[idx].name, fread);
    console.log(api.enumerateMatches('exports:*!fwrite')[idx].name, fwrite);

    var g_fargs = [];
    Interceptor.attach(fopen, {
        onEnter: function(args)
        {
            g_fargs.push(args[0].readCString());
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
            if(retval.toInt32()!=0)
            {
                console.log(ret_addr, 
                    "fopen", 
                    filepath,
                    "fp=" + retval);
            }
            g_fargs = []
        }
    })

    Interceptor.attach(fread, {
        onEnter: function(args)
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
            var fp = args[3];
            var offset = ftell(fp);
            console.log(ret_addr, 
                "fread(" + args[0]+", " + args[1]+", " + args[2] + ", " + fp + ")", 
                "offset=0x" + offset.toString(16));
        }
    })

    Interceptor.attach(fwrite, {
        onEnter: function(args)
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
            var fp = args[3];
            var offset = ftell(fp);
            console.log(ret_addr, 
                "fwrite(" + args[0]+", " + args[1]+", " + args[2] + ", " + fp + ")", 
                "offset=0x" + offset.toString(16));
        }
    })
}

function hook_winfile()
{
    const api = new ApiResolver("module");
    const CreateFileA = new NativeFunction(
        api.enumerateMatches('exports:*!CreateFileA')[0].address, 'pointer', 
        ['pointer', 'uint32', 'uint32', 'pointer', 'uint32', 'uint32', 'uint32']);
    const CreateFileW = new NativeFunction(
        api.enumerateMatches('exports:*!CreateFileW')[0].address, 'pointer', 
        ['pointer', 'uint32', 'uint32', 'pointer', 'uint32', 'uint32', 'uint32']);
    const CloseHandle = new NativeFunction(
        api.enumerateMatches('exports:*!CloseHandle')[0].address, 'bool', 
        ['pointer']);
    const SetFilePointer = new NativeFunction(
        api.enumerateMatches('exports:*!SetFilePointer')[0].address, 'uint32', 
        ['pointer', 'uint64', 'pointer', 'uint32']);
    const SetFilePointerEx = new NativeFunction(
        api.enumerateMatches('exports:*!SetFilePointerEx')[0].address, 'bool', 
        ['pointer', 'uint64', 'pointer', 'uint32']);
    const ReadFile = new NativeFunction(
        api.enumerateMatches('exports:*!ReadFile')[0].address, 'bool', 
        ['pointer', 'pointer', 'uint32', 'pointer', 'pointer']);
    const ReadFileEx = new NativeFunction(
        api.enumerateMatches('exports:*!ReadFileEx')[0].address, 'bool', 
        ['pointer', 'pointer', 'uint32', 'pointer', 'pointer']);
    const WriteFile = new NativeFunction(
        api.enumerateMatches('exports:*!WriteFile')[0].address, 'bool', 
        ['pointer', 'pointer', 'uint32', 'pointer', 'pointer']);
    const WriteFileEx = new NativeFunction(
        api.enumerateMatches('exports:*!WriteFileEx')[0].address, 'bool', 
        ['pointer', 'pointer', 'uint32', 'pointer', 'pointer']);

    console.log("CreateFileA at", CreateFileA);
    console.log("CreateFileW at", CreateFileW);
    console.log("CloseHandle at", CloseHandle);
    console.log("SetFilePointer at", SetFilePointer);
    console.log("SetFilePointerEx at", SetFilePointerEx);
    console.log("ReadFile at", ReadFile);
    console.log("ReadFileEx at", ReadFileEx);
    console.log("WriteFile at", WriteFile);
    console.log("WriteFileEx at", WriteFileEx);

    var g_fargs = [];
    Interceptor.attach(CreateFileA, {
        onEnter: function(args)
        {
            g_fargs.push(args[0].readCString());
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
            if(retval.toInt32()!=0)
            {
                console.log(ret_addr, 
                    "CreateFileA", 
                    filepath,
                    "hFile=" + retval);
            }
            g_fargs = []
        }
    })

    Interceptor.attach(CreateFileW, {
        onEnter: function(args)
        {
            g_fargs.push(args[0].readUtf16String());
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
            if(retval.toInt32()!=0)
            {
                console.log(ret_addr, 
                    "CreateFileW", 
                    filepath,
                    "hFile=" + retval);
            }
            g_fargs = []
        }
    })

    Interceptor.attach(ReadFile, {
        onEnter: function(args)
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
            var hfile = args[0];
            var offset = SetFilePointer(hfile, uint64(0), ptr(0), 1);
            console.log(ret_addr, "ReadFile", 
            "hFile=0x"+hfile.toString(16), "buf=0x"+args[1].toString(16),
            "sizeToRead="+args[2], "offset=0x" + offset.toString(16));
        }
    })

    Interceptor.attach(ReadFileEx, {
        onEnter: function(args)
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
            var hfile = args[0];
            var offset = SetFilePointer(hfile, uint64(0), ptr(0), 1);
            console.log(ret_addr, "ReadFileEx", 
            "hFile=0x"+hfile.toString(16), "buf=0x"+args[1].toString(16),
            "sizeToRead="+args[2], "offset=0x" + offset.toString(16));
        }
    })

    Interceptor.attach(WriteFile, {
        onEnter: function(args)
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
            var hfile = args[0];
            var offset = SetFilePointer(hfile, uint64(0), ptr(0), 1);
            console.log(ret_addr, "WriteFile", 
            "hFile=0x"+hfile.toString(16), "buf=0x"+args[1].toString(16),
            "sizeToWrite="+args[2], "offset=0x" + offset.toString(16));
        }
    })

    Interceptor.attach(WriteFileEx, {
        onEnter: function(args)
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
            var hfile = args[0];
            var offset = SetFilePointer(hfile, uint64(0), ptr(0), 1);
            console.log(ret_addr, "WriteFileEx", 
            "hFile=0x"+hfile.toString(16), "buf=0x"+args[1].toString(16),
            "sizeToWrite="+args[2], "offset=0x" + offset.toString(16));
        }
    })
}

hook_cfile();
hook_winfile();