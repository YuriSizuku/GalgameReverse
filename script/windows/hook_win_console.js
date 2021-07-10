function hook_console()
{
    var api = new ApiResolver("module");
    var __acrt_iob_func = new NativeFunction(
        api.enumerateMatches('exports:*!*acrt_iob_func')[0].address, 
        'pointer', ['uint']);
    var stdout = __acrt_iob_func(1);
    var freopen = new NativeFunction(
        api.enumerateMatches('exports:*!freopen')[0].address, 
        'pointer', ['pointer', 'pointer', 'pointer']);
    var AllocConsole = new NativeFunction(
        api.enumerateMatches('exports:*!AllocConsole')[0].address, 
        'int', []);
    
        AllocConsole()
    freopen(Memory.allocAnsiString("CONOUT$"), Memory.allocAnsiString("w"), stdout);
    console.log('AllocConsole at', AllocConsole, ", freopen at", freopen);
}

hook_console()