/*
    krkr_patch.c, 
	compile this dll to change locate and redirect patch path
	developed by devseed, v0.1

*/
#include<windows.h>
#include<stdio.h>

BOOL iat_hook_module(LPCSTR targetDllName, LPCSTR moduleDllName, PROC pfnOrg, PROC pfnNew)
{;
#ifdef _WIN64
#define VA_TYPE ULONGLONG
#else
#define VA_TYPE DWORD
#endif
    DWORD dwOldProtect = 0;
    VA_TYPE imageBase = (VA_TYPE)GetModuleHandleA(moduleDllName);
    LPBYTE pNtHeader = (LPBYTE)(*(DWORD *)((LPBYTE)imageBase + 0x3c) + imageBase); 
#ifdef _WIN64
    VA_TYPE impDescriptorRva = *((DWORD*)&pNtHeader[0x90]);
#else
    VA_TYPE impDescriptorRva = *((DWORD*)&pNtHeader[0x80]); 
#endif
    PIMAGE_IMPORT_DESCRIPTOR pImpDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(imageBase + impDescriptorRva); 
    for (; pImpDescriptor->Name; pImpDescriptor++) // find the dll IMPORT_DESCRIPTOR
    {
        LPCSTR pDllName = (LPCSTR)(imageBase + pImpDescriptor->Name);
        if (!_stricmp(pDllName, targetDllName)) // ignore case
        {
            PIMAGE_THUNK_DATA pFirstThunk = (PIMAGE_THUNK_DATA)(imageBase + pImpDescriptor->FirstThunk);
            for (; pFirstThunk->u1.Function; pFirstThunk++) // find the iat function va
            {
                if (pFirstThunk->u1.Function == (VA_TYPE)pfnOrg)
                {
                    VirtualProtect((LPVOID)&pFirstThunk->u1.Function, 4, PAGE_EXECUTE_READWRITE, &dwOldProtect);
                    pFirstThunk->u1.Function = (VA_TYPE)pfnNew;
                    VirtualProtect((LPVOID)&pFirstThunk->u1.Function, 4, dwOldProtect, &dwOldProtect);
                    return TRUE;
                }
            }
        }
    }
    return FALSE;
}

BOOL iat_hook(LPCSTR targetDllName, PROC pfnOrg, PROC pfnNew)
{
    return iat_hook_module(targetDllName, NULL, pfnOrg, pfnNew);
}

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

HFONT WINAPI CreateFontIndirectW_hook(LOGFONTW *lplf)
{
    lplf->lfCharSet = GB2312_CHARSET;
    return CreateFontIndirectW(lplf);
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
    if(!iat_hook("Gdi32.dll", (PROC)CreateFontIndirectW, (PROC)CreateFontIndirectW_hook))
    {
        MessageBoxA(NULL, "CreateFontIndirectW iat hook failed!", "error", 0);
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