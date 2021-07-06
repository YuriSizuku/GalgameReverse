#include <windows.h>
#include <stdio.h>

#include "win_hook.h"
#ifndef _DEBUG
    
#endif

void dummy()
{

}

void redirect_ig_filepathw(LPCWSTR org_filepath, LPWSTR redirect_filepath)
{
    int start = wcslen(org_filepath);
    while (org_filepath[start] != L'/' && start > 0) { start--; }
    start++;
    if (!_wcsicmp(&org_filepath[start], L"system.iga"))
    {
        wcscpy(redirect_filepath, org_filepath);
        wcscpy(&redirect_filepath[start], L"system_chs.iga");
        wprintf(L"redirect to %ls\n", redirect_filepath);
    }
    else if (!_wcsicmp(&org_filepath[start], L"script.iga"))
    {
        wcscpy(redirect_filepath, org_filepath);
        wcscpy(&redirect_filepath[start], L"script_chs.iga");
        wprintf(L"redirect to  %ls\n", redirect_filepath);
    }
    else if (!_wcsicmp(&org_filepath[start], L"save"))
    {
        wcscpy(redirect_filepath, org_filepath);
        wcscpy(&redirect_filepath[start], L"save_chs");
        wprintf(L"redirect to  %ls\n", redirect_filepath);
    }
    else
    {
        start -= 2;

        int end = start + 1;
        while (org_filepath[start] != L'/' && start > 0) { start--; }
        start++;
        if (!_wcsnicmp(&org_filepath[start], L"save", 4))
        {
            wcscpy(redirect_filepath, org_filepath);
            wcscpy(&redirect_filepath[start], L"save_chs");
            wcscat(redirect_filepath, &org_filepath[end]);
            wprintf(L"redirect to %ls\n", redirect_filepath);
        }
        else
        {
            wcscpy(redirect_filepath, org_filepath);
        }
    }
}

HWND WINAPI CreateWindowExW_hook(
    DWORD     dwExStyle,
    LPCWSTR   lpClassName,
    LPCWSTR   lpWindowName,
    DWORD     dwStyle,
    int       X,
    int       Y,
    int       nWidth,
    int       nHeight,
    HWND      hWndParent,
    HMENU     hMenu,
    HINSTANCE hInstance,
    LPVOID    lpParam
)
{
    return CreateWindowExW(dwExStyle, lpClassName, L"天之少女【穗见学园汉化组】_v1.1",
        dwStyle, X, Y, nWidth, nHeight, hWndParent, hMenu, hInstance, lpParam);
}

HMODULE WINAPI LoadLibraryExW_redirect(
    LPCWSTR lpLibFileName,
    HANDLE  hFile,
    DWORD   dwFlags
)
{
    wchar_t filename[1024];
    wprintf(L"LoadLibraryExW %ls\n", lpLibFileName);
    if (!_wcsicmp(lpLibFileName, L"./plugin/Script.dll"))
    {
        wcscpy(filename, L"./plugin/Script_chs.dll");
        wprintf(L"redirect to %ls\n", filename);
    }
    else if (!_wcsicmp(lpLibFileName, L"./plugin/D3D9Font.dll"))
    {
        wcscpy(filename, L"./plugin/D3D9Font_chs.dll");
        wprintf(L"redirect to %ls\n", filename);
    }
    else if (!_wcsicmp(lpLibFileName, L"./plugin/D3D9Font.dll"))
    {
        wcscpy(filename, L"./plugin/D3D9Font_chs.dll");
        wprintf(L"redirect to %ls\n", filename);
    }
    else
    {
        wcscpy(filename, lpLibFileName);
    }
    return LoadLibraryExW(filename, hFile, dwFlags);
}

HANDLE WINAPI CreateFileA_redirect(
    LPCSTR                lpFileName,
    DWORD                 dwDesiredAccess,
    DWORD                 dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD                 dwCreationDisposition,
    DWORD                 dwFlagsAndAttributes,
    HANDLE                hTemplateFile
)
{
    printf("CreateFileA %s\n", lpFileName);
    return CreateFileA(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
}

BOOL WINAPI CreateDirectoryW_redirect(
    LPCWSTR               lpPathName,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes
)
{
    wchar_t buf[1024];
    wprintf(L"CreateDirectoryW %ls\n", lpPathName);
    int start = wcslen(lpPathName);
    while (lpPathName[start] != L'/'&& start>0) { start--; }
    start++;
    if (!_wcsicmp(&lpPathName[start], L"save"))
    {
        wcscpy(buf, lpPathName);
        wcscpy(&buf[start], L"save_chs");
        wprintf(L"redirect to %ls\n", buf);
    }
    else
    {
        wcscpy(buf, lpPathName);
    }
    return CreateDirectoryW(buf, lpSecurityAttributes);
}

DWORD WINAPI GetFileAttributesW_redirect(
    LPWSTR lpFileName
)
{
    wchar_t redirect_path[1024];
    wprintf(L"GetFileAttributesW %ls\n", lpFileName);
    redirect_ig_filepathw(lpFileName, redirect_path);
    return GetFileAttributesW(redirect_path);
}

HANDLE WINAPI CreateFileW_redirect(
    LPCWSTR lpFileName,
    DWORD dwDesiredAccess,
    DWORD dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes,
    HANDLE hTemplateFile
)
{
    wchar_t redirect_path[1024];
    wprintf(L"CreateFileW %ls\n", lpFileName);
    redirect_ig_filepathw(lpFileName, redirect_path);
    return CreateFileW(redirect_path, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
}

void install_window_hook()
{
    if (!iat_hook("user32.dll",
        GetProcAddress(GetModuleHandleA("user32.dll"), "CreateWindowExW"),
        (PROC)CreateWindowExW_hook))
    {
        MessageBoxA(NULL, "IAT CreateWindowExW_hook hook failed!", "ERROR", 0);
    }
}

void install_himorogi_hook()
{
    LoadLibraryA("./Plugin/Himorogi.dll");
    
    if (!iat_hook_module("kernel32.dll", "Himorogi.dll",
        GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryExW"),
        (PROC)LoadLibraryExW_redirect))
    {
        MessageBoxA(NULL, "Himorogi.dll IAT LoadLibraryExW hook failed!", "ERROR", 0);
    }
    if (!iat_hook_module("kernel32.dll", "Himorogi.dll",
        GetProcAddress(GetModuleHandleA("kernel32.dll"), "CreateDirectoryW"),
        (PROC)CreateDirectoryW_redirect))
    {
        MessageBoxA(NULL, "Himorogi.dll IAT CreateDirectoryW  hook failed!", "ERROR", 0);
    }
    if (!iat_hook_module("kernel32.dll", "Himorogi.dll",
        GetProcAddress(GetModuleHandleA("kernel32.dll"), "GetFileAttributesW"),
        (PROC)GetFileAttributesW_redirect))
    {
        MessageBoxA(NULL, "Himorogi.dll IAT GetFileAttributesW  hook failed!", "ERROR", 0);
    }

    if (!iat_hook_module("kernel32.dll", "Himorogi.dll",
        GetProcAddress(GetModuleHandleA("kernel32.dll"), "CreateFileW"),
        (PROC)CreateFileW_redirect))
    {
        MessageBoxA(NULL, "Himorogi.dll IAT CreateFileW hook failed!", "ERROR", 0);
    }

}

void install_hook()
{
#ifdef _DEBUG
    AllocConsole();
    //MessageBoxA(0, "debug install", "debug", 0);
    freopen("CONOUT$", "w", stdout);
    printf("install hook\n");
#endif
    install_window_hook();
    install_himorogi_hook();
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        install_hook();
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}