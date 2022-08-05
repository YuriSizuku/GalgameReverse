/**
 *  for SorairoNoOrgan chs support
 *  v0.1, developed by devseed
 *  
*/

#include <windows.h>
#include <stdio.h>

#define WINHOOK_IMPLEMENTATION
#include <winhook.h>

HMODULE WINAPI LoadLibraryExA_hook(
    LPCSTR lpLibFileName, HANDLE hFile, DWORD  dwFlags)
{
    printf("LoadLibraryExA %s\n", lpLibFileName);
    if(strstr(lpLibFileName, "sc00.dll"))
    {
        strcpy((char*)lpLibFileName, "sc00.dll");
    }
    return LoadLibraryExA(lpLibFileName, hFile, dwFlags);
}

LPSTR WINAPI CharNextA_hook(LPCSTR lpsz)
{
    if ((*((unsigned char*)lpsz)) < 0x80) 
        return CharNextA(lpsz);
    else return (LPSTR)(lpsz+2);
}

HFONT WINAPI CreateFontIndirectA_hook(LOGFONTA *lplf)
{
    //printf("in CreateFontIndirectA_hook\n");
    lplf->lfCharSet = GB2312_CHARSET;
    strcpy(lplf->lfFaceName, "simhei");
    return CreateFontIndirectA(lplf);
}

int WINAPI MultiByteToWideChar_hook(
	UINT CodePage, DWORD dwFlags,
	LPCCH lpMultiByteStr, int cbMultiByte,
	LPWSTR lpWideCharStr, int cchWideChar
)
{
    return MultiByteToWideChar(CodePage, 
        dwFlags, lpMultiByteStr, cbMultiByte, 
        lpWideCharStr, cchWideChar);
}

void install_residenthook()
{
    if(!LoadLibraryA("resident.dll"))
    {
        MessageBoxA(NULL, "load resident.dll failed!", "error", 0);
    }
    if(!winhook_iathookmodule("User32.dll", "resident.dll", 
        GetProcAddress(GetModuleHandleA("user32.dll"), 
        "CharNextA"), (PROC)CharNextA_hook))
    {
        MessageBoxA(NULL, "iathook resident.dll CharNextA failed!", "error", 0);
    }
    if(!winhook_iathookmodule("gdi32.dll", "resident.dll", 
        GetProcAddress(GetModuleHandleA("gdi32.dll"), 
        "CreateFontIndirectA"), (PROC)CreateFontIndirectA_hook))
    {
        MessageBoxA(NULL, "iathook resident.dll CreateFontIndirectA failed!", "error", 0);
    }
    printf("install_residenthook finished!\n");
}

void install_schook()
{
    if(!LoadLibraryA("sc00.dll"))
    {
        MessageBoxA(NULL, "load sc00.dll failed!", "error", 0);
    }
    if(!winhook_iathookmodule("Kernel32.dll", "sc00.dll", 
        GetProcAddress(GetModuleHandleA("Kernel32.dll"), 
        "MultiByteToWideChar"), (PROC)MultiByteToWideChar_hook))
    {
        MessageBoxA(NULL, "iathook sc00.dll MultiByteToWideChar failed!", "error", 0);
    }
    if(!winhook_iathookmodule("User32.dll", "sc00.dll", 
        GetProcAddress(GetModuleHandleA("user32.dll"), 
        "CharNextA"), (PROC)CharNextA_hook))
    {
        MessageBoxA(NULL, "iathook sc00.dll CharNextA failed!", "error", 0);
    }
    if(!winhook_iathookmodule("gdi32.dll", "sc00.dll", 
        GetProcAddress(GetModuleHandleA("gdi32.dll"), 
        "CreateFontIndirectA"), (PROC)CreateFontIndirectA_hook))
    {
        MessageBoxA(NULL, "iathook sc00.dll CreateFontIndirectA failed!", "error", 0);
    }
    printf("install_schook finished!\n");
}

void install_exehook()
{
    if(!winhook_iathook("Kernel32.dll", 
        GetProcAddress(GetModuleHandleA("Kernel32.dll"), 
        "LoadLibraryExA"), (PROC)LoadLibraryExA_hook))
    {
        MessageBoxA(NULL, "iathook LoadLibraryExA failed!", "error", 0);
    }
    printf("install_exehook finished!\n");
}

void install_hooks()
{
    #ifdef _DEBUG
    AllocConsole();
    //MessageBoxA(0, "debug install", "debug", 0);
    freopen("CONOUT$", "w", stdout);
    printf("sorairo_patch, v0.1,  build in 220607\n");
    #endif
    install_exehook();
    install_residenthook();
    install_schook();
}

BOOL WINAPI DllMain(
    HINSTANCE hinstDLL,  // handle to DLL module
    DWORD fdwReason,     // reason for calling function
    LPVOID lpReserved )  // reserved
{
    switch( fdwReason ) 
    { 
        case DLL_PROCESS_ATTACH:
            install_hooks();
            break;
        case DLL_THREAD_ATTACH:
            break;
        case DLL_THREAD_DETACH:
            break;
        case DLL_PROCESS_DETACH:
            break;
    }
    return TRUE;
}