/**
 *  for nscripter translation support and redirect arc file
 *  v0.1, developed by devseed
 * 
 *  tested game: 
 *    魔女の処刑日　～上弦の月は私を見下し～　前編　
 *     
*/

#include <windows.h>
#include <stdio.h>
#include <shlwapi.h>
#include <locale.h>

__declspec(dllexport) void dummy()
{

}

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

#define REDIRECT_DIRA "override_cn"
LPSTR _RedirectArcA(LPSTR lpFileName)
{
    static char tmppath[MAX_PATH] = {0};
    tmppath[0] = 0;
    char *name = PathFindFileNameA(lpFileName);
    if(name && (strstr(name, ".arc")||strstr(name, ".ARC")
    || strstr(name, ".dat")||strstr(name, ".DAT"))
    || strstr(name, ".txt")||strstr(name, ".txt"))
    {
        strncpy(tmppath, lpFileName, name - lpFileName);
        tmppath[name - lpFileName] = 0;
        strcat(tmppath, REDIRECT_DIRA "\\");
        strcat(tmppath, name);
        if(PathFileExistsA(tmppath))
        {
            printf("CreateFileA redirect %s -> %s\n", lpFileName, tmppath);
            // strcpy(lpFileName, tmppath);
            return tmppath;
        }
    }
    return NULL;
}

HANDLE WINAPI CreateFileA_hook(
    IN LPSTR lpFileName,
    IN DWORD dwDesiredAccess,
    IN DWORD dwShareMode,
    IN OPTIONAL LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    IN DWORD dwCreationDisposition,
    IN DWORD dwFlagsAndAttributes,
    IN OPTIONAL HANDLE hTemplateFile)
{
    LPSTR targetpath = _RedirectArcA(lpFileName);
    if(!targetpath) targetpath = lpFileName;
    return CreateFile(targetpath, dwDesiredAccess, dwShareMode, 
        lpSecurityAttributes, dwCreationDisposition, 
        dwFlagsAndAttributes, hTemplateFile);
}

int WINAPI MultiByteToWideChar_hook(
	UINT CodePage,
	DWORD  dwFlags,
	LPCCH lpMultiByteStr,
	int cbMultiByte,
	LPWSTR  lpWideCharStr,
	int cchWideChar)
{
    if(CodePage==0) CodePage=936;
	int ret = MultiByteToWideChar(CodePage, dwFlags, lpMultiByteStr, 
        cbMultiByte, lpWideCharStr, cchWideChar);
    return ret;
}

int WINAPI WideCharToMultiByte_hook(
	UINT CodePage,
	DWORD dwFlags,
	LPCWCH lpWideCharStr,
	int cchWideChar,
	LPSTR lpMultiByteStr,
	int cbMultiByte,
	LPCCH lpDefaultChar,
	LPBOOL lpUsedDefaultChar
)
{
    if(CodePage==0) CodePage=936;
	int ret = WideCharToMultiByte(CodePage, dwFlags, lpWideCharStr, 
        cchWideChar, lpMultiByteStr, cbMultiByte, 
        lpDefaultChar, lpUsedDefaultChar);
    return ret;
}

HFONT WINAPI CreateFontA_hook(IN int cHeight, IN int cWidth,
    IN int cEscapement, IN int cOrientation, IN int cWeight, IN DWORD bItalic,
    IN DWORD bUnderline, IN DWORD bStrikeOut, IN DWORD iCharSet, 
    IN DWORD iOutPrecision, IN DWORD iClipPrecision, IN DWORD iQuality,
    IN DWORD iPitchAndFamily, IN OPTIONAL LPCSTR pszFaceName)
{
    return CreateFontA(cHeight, cWidth, cEscapement, cOrientation, 
        cWeight, bItalic, bUnderline, bStrikeOut, GB2312_CHARSET, 
        iOutPrecision, iClipPrecision, iQuality, iPitchAndFamily, "simhei");
}

int WINAPI EnumFontFamiliesExA_hook(HDC hdc, 
    LPLOGFONTA lpLogfont, FONTENUMPROCA lpProc,  
    LPARAM lParam, DWORD dwFlags)
{
    // in nscript, this can not be redirect by iathook, should use inline hook
    lpLogfont->lfCharSet = GB2312_CHARSET;
    printf("EnumFontFamiliesExA");
    return EnumFontFamiliesExA(hdc, lpLogfont, lpProc, lParam, dwFlags);
}


BOOL WINAPI SetWindowTextA_hook(
    IN HWND hWnd, IN OPTIONAL LPCSTR lpString)
{
    if(lpString)
    {
        static WCHAR lpwString[MAX_PATH] = {0};
        MultiByteToWideChar(936, 0, lpString, 
            strlen(lpString), lpwString, sizeof(lpwString));
        // wcscpy(lpwString, L"NSSS");
        printf("title: %s\n", lpString);
        wprintf(L"wstring title: %ls\n", lpwString);
        return SetWindowTextW(hWnd, lpwString);
    }
    else return SetWindowTextA(hWnd, lpString);
}

void install_hooks()
{
#ifdef _DEBUG
    AllocConsole();
    //MessageBoxA(0, "debug install", "debug", 0);
    freopen("CONOUT$", "w", stdout);
    system("chcp 936");
    setlocale(LC_ALL, "chs");
    printf("nscript_path, developed by devseed\n");
    printf("build in 20221117");
#endif
    // kernel32
    if(!iat_hook("kernel32.dll", GetProcAddress(
        GetModuleHandleA("kernel32.dll"), "CreateFileA"), 
        (PROC)CreateFileA_hook))
    {
        MessageBoxA(0, "CreateFileA hook error", "IAThook error", 0);
    }
    if(!iat_hook("kernel32.dll", GetProcAddress(
        GetModuleHandleA("kernel32.dll"), "MultiByteToWideChar"),
        (PROC)MultiByteToWideChar_hook))
    {
        MessageBoxA(0, "MultiByteToWideChar hook error", "IAThook error", 0);
    }
	if(!iat_hook("kernel32.dll", GetProcAddress(
        GetModuleHandleA("kernel32.dll"), "WideCharToMultiByte"), 
        (PROC)WideCharToMultiByte_hook))
    {
        MessageBoxA(0, "WideCharToMultiByte hook error", "IAThook error", 0);
    }
    
    // user32
    if(!iat_hook("user32.dll", GetProcAddress(
        GetModuleHandleA("user32.dll"), "SetWindowTextA"), 
        (PROC)SetWindowTextA_hook))
    {
        MessageBoxA(0, "SetWindowTextA hook error", "IAThook error", 0);
    }

    // gdi32
    if(!iat_hook("gdi32.dll", GetProcAddress(
        GetModuleHandleA("gdi32.dll"), "CreateFontA"), 
        (PROC)CreateFontA_hook))
    {
        MessageBoxA(0, "CreateFontA hook error", "IAThook error", 0);
    }

    if(!iat_hook("gdi32.dll", GetProcAddress(
        GetModuleHandleA("gdi32.dll"), "EnumFontFamiliesExA"), 
        (PROC)EnumFontFamiliesExA_hook))
    {
        MessageBoxA(0, "EnumFontFamiliesExA hook error", "IAThook error", 0);
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