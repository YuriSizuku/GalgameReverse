/**
 *  for aikimi.exe (livemaker) chs supports
 *  v0.1.1, developed by devseed
 *  
*/
#include <windows.h>
#include <stdio.h>
#define WINHOOK_IMPLEMENTATION
#include "winhook.h"

// must have export function, or 0xc000007b failed
__declspec(dllexport) void dummy()
{

}

// not worked for geting the originnal overlay file
// the offset calc is different, or hard encoded offset
DWORD WINAPI GetModuleFileNameA_hook(
    HMODULE hModule, LPSTR lpFilename, DWORD nSize)
{
    DWORD ret = GetModuleFileNameA(hModule, lpFilename, nSize);
    int i = strlen(lpFilename);
    while(i>=0 && lpFilename[i]!='\\') i--;
    i++;
    strcpy(&lpFilename[i], "aikimi.exe");
    printf("GetModuleFileNameA %s\n", lpFilename);
    return ret;
}

typedef HANDLE(WINAPI *PFN_CreateFile) (
    LPCSTR lpFileName,
    DWORD dwDesiredAccess,
    DWORD dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes,
    HANDLE hTemplateFile);

PFN_CreateFile g_pfnOldCreateFile;

// not worked, this game is very wired
HANDLE WINAPI CreateFileA_hook(
    LPCSTR lpFileName,
    DWORD dwDesiredAccess,
    DWORD dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes,
    HANDLE hTemplateFile)
{
    printf("CreateFileA_hook %s\n", lpFileName);
    int i = strlen(lpFileName);
    while(i>=0 && lpFileName[i]!='\\') i--;
    i++;
    if(strcmp(lpFileName+i, "00000001.lsb")==0)
    {
        strcpy((char*)(lpFileName+i), "00000001_chs.lsb");
        printf("redirect 00000001_chs done!\n");
    }
    return g_pfnOldCreateFile(lpFileName, dwDesiredAccess, 
        dwShareMode, lpSecurityAttributes, dwCreationDisposition, 
        dwFlagsAndAttributes, hTemplateFile);
}

HFONT WINAPI CreateFontIndirectA_hook(LOGFONTA *lplf)
{
    lplf->lfCharSet = GB2312_CHARSET;
    strcpy(lplf->lfFaceName , "simhei");
    return CreateFontIndirectA(lplf);
}

BOOL WINAPI IsDBCSLeadByteEx_hook(UINT CodePage, BYTE TestChar)
{
    return IsDBCSLeadByteEx(936, TestChar);
}

BOOL WINAPI SetWindowTextW_hook(HWND hwnd, LPCWSTR lpString)
{
    wcscpy((wchar_t*)lpString, L"深愛着君的居所");
    return SetWindowTextW(hwnd, lpString);
}

void patch_strings()
{
    
    void *addrs[] = {(void*)0x001BE290, (void*)0x001BE270};
    const int n = sizeof(addrs)/sizeof(void*);
    char *strs[] = {
        "\x89\xe6\x96\xca\x90\xd8\x91\xd6\x00",
        "\x8F\x49\x97\xB9\x00"
    };
    char *strs_chs[] = {
        "\xBB\xAD\xC3\xE6\xC7\xD0\xBB\xBB\x00",
        "\xBD\xE1\xCA\xF8"
    };
    size_t bufsizes[n];
    for(int i=0;i<n;i++) 
    {
        if(memcmp(addrs[i], strs[i], strlen(strs[i]))==0)
        {
            bufsizes[i] = strlen(strs_chs[i]);
        }
        else
        {
            bufsizes[i] = 0;
        }
    }
    winhook_patchmemorys(addrs, (void**)strs_chs, bufsizes, n);
}

void patch_sjis()
{
    int codepage = 936;
    winhook_patchmemory((void*)0x1C2D1C, &codepage,4); 
}

void install_iathooks()
{    
    if(!winhook_iathook("Kernel32.dll", GetProcAddress(
        GetModuleHandleA("Kernel32.dll"), "IsDBCSLeadByteEx"),
        (PROC)IsDBCSLeadByteEx_hook))
    {
        MessageBoxA(0, "IsDBCSLeadByteEx hook error", "IAThook error", 0);
    }
    if(!winhook_iathook("User32.dll", GetProcAddress(
        GetModuleHandleA("User32.dll"), "SetWindowTextW"),
        (PROC)SetWindowTextW_hook))
    {
        MessageBoxA(0, "SetWindowTextW hook error", "IAThook error", 0);
    }
    if(!winhook_iathook("Gdi32.dll", GetProcAddress(
        GetModuleHandleA("Gdi32.dll"), "CreateFontIndirectA"),
        (PROC)CreateFontIndirectA_hook))
    {
        MessageBoxA(0, "CreateFontIndirectA hook error", "IAThook error", 0);
    }
}

void install_inlinehooks()
{
    void* pftarget[] = {GetProcAddress(
        GetModuleHandleA("Kernel32.dll"), 
        "IsDBCSLeadByteEx"), NULL};
    void* pfnold[] = {pftarget[0], NULL};
    void* pfnnew[] = {CreateFileA_hook, NULL};
    winhook_inlinehooks(pftarget, pfnnew, pfnold, 1);
    g_pfnOldCreateFile = pfnold[0];
}

void install_hooks()
{
    #ifdef _DEBUG
    AllocConsole();
    freopen("CONOUT$", "w", stdout);
    printf("install hook, v0.1.1, build 220504 \n");
    #endif

    install_iathooks();
    patch_strings();
    patch_sjis();
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
/*
 *  history
 *  v0.1, initial version 
 *  v0.1.1, compatibale with gcc, tcc
 */