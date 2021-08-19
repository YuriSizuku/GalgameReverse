/*
    win_console.js, by devseed, v0.1
    use this script to allocate a console on some program
*/

function hook_console()
{
    const api = new ApiResolver("module");
    const __acrt_iob_func = new NativeFunction(
        api.enumerateMatches('exports:*!*acrt_iob_func')[0].address, 
        'pointer', ['uint']);
    const stdout = __acrt_iob_func(1);
    const freopen = new NativeFunction(
        api.enumerateMatches('exports:*!freopen')[0].address, 
        'pointer', ['pointer', 'pointer', 'pointer']);
    const AllocConsole = new NativeFunction(
        api.enumerateMatches('exports:*!AllocConsole')[0].address, 
        'int', []);
    
        AllocConsole()
    freopen(Memory.allocAnsiString("CONOUT$"), Memory.allocAnsiString("w"), stdout);
    console.log('AllocConsole at', AllocConsole, ", freopen at", freopen);
}

hook_console()