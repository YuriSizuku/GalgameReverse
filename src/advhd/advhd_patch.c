/**
 *  for AdvHD.EXE chs 
 *  gbk support and overide arc file
 *  tested in BlackishHouse (v1.6.2.1)
 *      v0.1, developed by devseed
 *  
*/

#include <stdio.h>
#include <windows.h>
#include <shlwapi.h>
#include <locale.h>
#define WINHOOK_IMPLEMENTATION
#include "winhook.h"

#define OVERRIDE_DIR L"override"
PVOID g_pfnTargets[] = {NULL};
PVOID g_pfnNews[] = {NULL}; 
PVOID g_pfnOlds[] = {NULL};

typedef HANDLE (WINAPI *PFN_CreateFileW)(
    _In_ LPCWSTR lpFileName,
    _In_ DWORD dwDesiredAccess,
    _In_ DWORD dwShareMode,
    _In_opt_ LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    _In_ DWORD dwCreationDisposition,
    _In_ DWORD dwFlagsAndAttributes,
    _In_opt_ HANDLE hTemplateFile);

HANDLE WINAPI CreateFileW_hook(
    _In_ LPWSTR lpFileName,
    _In_ DWORD dwDesiredAccess,
    _In_ DWORD dwShareMode,
    _In_opt_ LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    _In_ DWORD dwCreationDisposition,
    _In_ DWORD dwFlagsAndAttributes,
    _In_opt_ HANDLE hTemplateFile
)
{
    static wchar_t tmppath[MAX_PATH];
    
    wchar_t *name = PathFindFileNameW(lpFileName);
    if(name && wcsstr(name, L".arc"))
    {
        wcsncpy(tmppath, lpFileName, name - lpFileName);
        tmppath[name - lpFileName] = 0;
        wcscat(tmppath, OVERRIDE_DIR L"\\");
        wcscat(tmppath, name);
        if(PathFileExistsW(tmppath))
        {
            wprintf(L"CreateFileW redirect %ls->%ls\n", lpFileName, tmppath);
            wcscpy(lpFileName, tmppath);
        }
    }

    PFN_CreateFileW pfnCreateFileW = (PFN_CreateFileW)g_pfnOlds[0];
    return pfnCreateFileW(lpFileName, dwDesiredAccess, dwShareMode, 
        lpSecurityAttributes, dwCreationDisposition, 
        dwFlagsAndAttributes, hTemplateFile);
}

int WINAPI MultiByteToWideChar_hook(
    _In_ UINT CodePage,
    _In_ DWORD dwFlags,
    _In_ LPCCH lpMultiByteStr,
    _In_ int cbMultiByte,
    _Out_ LPWSTR lpWideCharStr,
    _In_ int cchWideChar
)
{
    UINT cp = 936;
    // PNA
    if(strstr(lpMultiByteStr,"\x2e\x50\x4e\x41"))
    {
        cp = CodePage;
    }
    // printf("mbtwc %s\n", lpMultiByteStr);
    int ret = MultiByteToWideChar(cp, dwFlags, 
        lpMultiByteStr, cbMultiByte, 
        lpWideCharStr, cchWideChar);
    // wprintf(L"mbtwc %ls\n", lpWideCharStr);
    return ret;
}

int WINAPI WideCharToMultiByte_hook(
    _In_ UINT CodePage,
    _In_ DWORD dwFlags,
    _In_ LPCWCH lpWideCharStr,
    _In_ int cchWideChar,
    _Out_ LPSTR lpMultiByteStr,
    _In_ int cbMultiByte,
    _In_opt_ LPCCH lpDefaultChar,
    _Out_opt_ LPBOOL lpUsedDefaultChar
)
{
    int ret = WideCharToMultiByte(936, dwFlags, 
        lpWideCharStr, cchWideChar, 
        lpMultiByteStr, cbMultiByte, 
        lpDefaultChar, lpUsedDefaultChar);
    // wprintf(L"wctmb %ls\n", lpWideCharStr);
    return ret;
}

HFONT WINAPI CreateFontIndirectW_hook(_In_ LOGFONTW *lplf)
{
    lplf->lfCharSet = GB2312_CHARSET;
    wcscpy(lplf->lfFaceName, L"simhei");
    return CreateFontIndirectW(lplf);
}

void install_iathooks()
{
    if(!winhook_iathook("Kernel32.dll", 
        GetProcAddress(GetModuleHandleA("Kernel32.dll"), 
        "MultiByteToWideChar"), (PROC)MultiByteToWideChar_hook))
    {
        MessageBoxA(NULL, "MultiByteToWideChar iathook failed!", "error", 0);
    }
    if(!winhook_iathook("Kernel32.dll", 
        GetProcAddress(GetModuleHandleA("Kernel32.dll"), 
        "WideCharToMultiByte"), (PROC)WideCharToMultiByte_hook))
    {
         MessageBoxA(NULL, "WideCharToMultiByte iathook failed!", "error", 0);
    }
    if(!winhook_iathook("Gdi32.dll", 
        GetProcAddress(GetModuleHandleA("Gdi32.dll"), 
        "CreateFontIndirectW"), (PROC)CreateFontIndirectW_hook))
    {
         MessageBoxA(NULL, "CreateFontIndirectW iathook failed!", "error", 0);
    }
}

void install_inlinehooks()
{
    g_pfnTargets[0] =  (PVOID)GetProcAddress(
        GetModuleHandleA("Kernel32.dll"), 
        "CreateFileW"),
    g_pfnNews[0] = (PVOID)CreateFileW_hook;
    winhook_inlinehooks(g_pfnTargets, 
        g_pfnNews, g_pfnOlds, 
        sizeof(g_pfnTargets)/sizeof(PVOID));
}

void install_hooks()
{
#ifdef _DEBUG
    AllocConsole();
    freopen("CONOUT$", "w", stdout);
    system("chcp 936");
    setlocale(LC_ALL, "chs");
    printf("install hook, v0.1, build in 220803\n");
    wprintf(L"汉化测试！\n");
#endif
    install_inlinehooks();
    install_iathooks();
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