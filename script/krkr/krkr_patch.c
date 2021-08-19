/*
    krkr_patch.c, by devseed, v0.1
    compile this dll to change locate and redirect patch path
*/
#include<windows.h>
#include<stdio.h>
#include "win_hook.h"

__declspec(dllexport) void dummy()
{

}

int WINAPI MultiByteToWideChar_hook(
  UINT CodePage,
  DWORD  dwFlags,
  LPCCH lpMultiByteStr,
  int cbMultiByte,
  LPWSTR  lpWideCharStr,
  int cchWideChar)
{
    return MultiByteToWideChar(932, dwFlags, lpMultiByteStr, cbMultiByte, lpWideCharStr, cchWideChar);
}

HANDLE WINAPI CreateFileW_hook(
    LPCWSTR lpFileName,
    DWORD dwDesiredAccess,
    DWORD dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes,
    HANDLE hTemplateFile)
{
    wchar_t redirect_name[1024];
    size_t name_start;
    for (size_t i=wcslen(lpFileName);i>=0;i--)
    {
        if(lpFileName[i]==L'\\'|| lpFileName[i]==L'/')
        {
            name_start = i+1;
            break;
        }
    }

    // redirect patch
    if(!wcsncmp(&lpFileName[name_start], L"patch", 5))
    {
       size_t name_end=name_start+5;
       while (lpFileName[name_end]!=L'.' && lpFileName[name_end]!=0) name_end++;
       wcsncpy(redirect_name, lpFileName, name_end);
       redirect_name[name_end]=0;
       wcscat(redirect_name, L"_chs.xp3");
       wprintf(L"%ls %ls\n", lpFileName, redirect_name);
    }
    else
    {
        wcscpy(redirect_name, lpFileName);
    }

    return CreateFileW(redirect_name, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
}

void install_hooks()
{
#ifdef _DEBUG
    AllocConsole();
    //MessageBoxA(0, "debug install", "debug", 0);
    freopen("CONOUT$", "w", stdout);
    printf("install hook\n");
#endif
    if(!iat_hook("kernel32.dll", (PROC)MultiByteToWideChar, 
        (PROC)MultiByteToWideChar_hook))
    {
        MessageBoxA(0, "MultiByteToWideChar hook error", "IAThook error", 0);
    }
    if(!iat_hook("kernel32.dll", 
        (PROC)CreateFileW, (PROC)CreateFileW_hook))
    {
        MessageBoxA(0, "CreateFileW hook error", "IAThook error", 0);
    }
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        install_hooks();
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}