/**
 * majiro engine, localization support
 *   v0.2, developed by devseed
 * 
 * tested game:
 *   そらいろ (ねこねこソフト) v1.1
 *   (patch=+38C0:C3;+1903B:B8A1;+19087:B8A1;+19A7A:B8A1;+1905D:B9A1;+19AF0:B9A1)
 * 
 *   ルリのかさね ～いもうと物語り (ねこねこソフト)
 *   
 * 
 * override/config.ini // number must be decimal except patchpattern
 *   charset=128
 *   font=simhei
 *   patch_gbk=1
 *   patch=addr:bytes;...
*/

#include <stdio.h>
#include <windows.h>
#include <shlwapi.h>
#include <locale.h>

// winhook.h v0.3
#define WINHOOK_IMPLEMENTATION
#ifdef USE_COMPAT
#include "winhook_v310.h"
#else
#include "winhook.h"
#endif

// winpe.h v0.3.5
#define WINPE_IMPLEMENTATION
#ifdef USE_COMPAT
#include "winpe_v350.h"
#else
#include "winpe.h"
#endif

#define CONFIG_PATH "override\\config.ini"
#define REDIRECT_DIRA "override"
#define REDIRECT_DIRW L"override"

PVOID g_pfnTargets[1] = {NULL};
PVOID g_pfnNews[1] = {NULL}; 
PVOID g_pfnOlds[1] = {NULL};
HANDLE g_mutexs[1] = {NULL};
FONTENUMPROCA g_fontproc = NULL;

struct majirocfg_t{
    int charset;
    int codepage;
    int patch_gbk;
    char font[MAX_PATH];
    char patch[1024];
};

struct majirocfg_t g_majirocfg = 
{
    .charset=0x0, 
    .codepage=0x0,
    .patch_gbk=0, 
    .font="\0",
    .patch={0}
};

#if 1 // iat hooks
LPSTR _RedirectFileA(LPCSTR path)
{
    static char tmppath[MAX_PATH] = {0};
    tmppath[0] = 0;
    strcat(tmppath, REDIRECT_DIRA "\\");
    LPCSTR name = strrchr(path, '\\');
    if(!name) name = path;
    
    // try rediect savedata
    if(strstr(path, "savedata")){
        strcat(tmppath, "savedata\\");
        strcat(tmppath, name);
        printf("CreateFileA redirect %s -> %s\n", path, tmppath);
        return tmppath;
    }

    // try redirect normal file
    strcat(tmppath, name);
    if(PathFileExistsA(tmppath))
    {
        printf("CreateFileA redirect %s -> %s\n", path, tmppath);
        return tmppath;
    }
    return NULL;
}

LPWSTR _RedirectFileW(LPCWSTR path)
{
    static WCHAR tmppath[MAX_PATH] = {0};
    tmppath[0] = 0;
    wcscat(tmppath, REDIRECT_DIRA L"\\");
    LPCWSTR name = wcsstr(path, L"\\");
    if(!name) name = path;
    
    // try rediect savedata
    if(wcsstr(path, L"savedata")){
        wcscat(tmppath, L"savedata\\");
        wcscat(tmppath, name);
        wprintf(L"CreateFileW redirect %ls -> %ls\n", path, tmppath);
        return tmppath;
    }

    // try redirect normal file
    wcscat(tmppath, name);
    if(PathFileExistsW(tmppath))
    {
        wprintf(L"CreateFileW redirect %ls -> %ls\n", path, tmppath);
        return tmppath;
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
    // printf("CreateFileA %s\n", lpFileName);
    LPSTR targetpath = _RedirectFileA(lpFileName);
    if(!targetpath) targetpath = lpFileName;
    HANDLE res = CreateFileA(targetpath, dwDesiredAccess, dwShareMode, 
        lpSecurityAttributes, dwCreationDisposition, 
        dwFlagsAndAttributes, hTemplateFile);
    return res;
}

HANDLE WINAPI CreateFileW_hook(
    IN LPWSTR lpFileName,
    IN DWORD dwDesiredAccess,
    IN DWORD dwShareMode,
    IN OPTIONAL LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    IN DWORD dwCreationDisposition,
    IN DWORD dwFlagsAndAttributes,
    IN OPTIONAL HANDLE hTemplateFile)
{
    // wprintf(L"CreateFileW %ls\n", lpFileName);
    LPWSTR targetpath = _RedirectFileW(lpFileName);
    if(!targetpath) targetpath = lpFileName;
    HANDLE res = CreateFileW(targetpath, dwDesiredAccess, dwShareMode, 
        lpSecurityAttributes, dwCreationDisposition, 
        dwFlagsAndAttributes, hTemplateFile);
    return res;

}

HFONT WINAPI CreateFontIndirectA_hook(LOGFONTA *lplf)
{   
    if(g_majirocfg.charset) lplf->lfCharSet = g_majirocfg.charset;
    if(g_majirocfg.font[0]) strcpy(lplf->lfFaceName , g_majirocfg.font);
    return CreateFontIndirectA(lplf);
}

BOOL CALLBACK fontproc_hook(LPLOGFONT lplf, TEXTMETRICA* lpntm, DWORD FontType, LPARAM aFontCount) 
{
    if(g_majirocfg.charset) 
    {
        lplf->lfCharSet = SHIFTJIS_CHARSET; // as the game accept sjis charset only
    }
    if(g_fontproc) return g_fontproc(lplf, lpntm, FontType, aFontCount);
    return FALSE;
}

int WINAPI EnumFontFamiliesA_hook(IN HDC hdc, 
    IN LPCSTR lpLogfont, IN FONTENUMPROCA lpProc, IN LPARAM lParam)
{
    g_fontproc = lpProc;
    return EnumFontFamiliesA(hdc, lpLogfont, (FONTENUMPROCA)fontproc_hook, lParam);
}

UINT WINAPI GetACP_hook()
{
    UINT CodePage = GetACP();
    if(g_majirocfg.codepage) CodePage = g_majirocfg.codepage;
    return CodePage;
}

BOOL WINAPI GetCPInfo_hook(IN UINT CodePage, OUT LPCPINFO lpCPInfo)
{
    if(g_majirocfg.codepage) CodePage = g_majirocfg.codepage;
    BOOL res = GetCPInfo(CodePage, lpCPInfo);
    return res;
}

int WINAPI MultiByteToWideChar_hook(
  UINT CodePage,
  DWORD  dwFlags,
  LPCCH lpMultiByteStr,
  int cbMultiByte,
  LPWSTR  lpWideCharStr,
  int cchWideChar)
{
    if(CodePage==0) CodePage = g_majirocfg.codepage;
    int ret = MultiByteToWideChar(CodePage, dwFlags, 
        lpMultiByteStr, cbMultiByte, lpWideCharStr, cchWideChar);
    // wprintf(L"mbtowc %ls\n", lpWideCharStr);
    return ret;
}

int WINAPI WideCharToMultiByte_hook(
    IN UINT CodePage,
    IN DWORD dwFlags,
    IN LPCWCH lpWideCharStr,
    IN int cchWideChar,
    OUT LPSTR lpMultiByteStr,
    IN int cbMultiByte,
    IN OPTIONAL LPCCH lpDefaultChar,
    OUT OPTIONAL LPBOOL lpUsedDefaultChar)
{
    if(CodePage==0) CodePage = g_majirocfg.codepage;
    int ret = WideCharToMultiByte(CodePage, dwFlags, 
        lpWideCharStr, cchWideChar, 
        lpMultiByteStr, cbMultiByte, 
        lpDefaultChar, lpUsedDefaultChar);
    // wprintf(L"wctmb %ls\n", lpWideCharStr);
    return ret;
}
#endif

#if 1 // inline hooks
#endif

#if 1 // patches
void patch_gbk()
{
    HMODULE base = GetModuleHandleA(NULL);
    void* addr_start = (void*)base;
    void* addr_end = (void*)((size_t)base + winpe_imagesizeval((void*)base, 0));
    char patchbytes[3] = {0};
    
    // 68 75 81 00 00 push 8175h
    // strcpy(patchbytes, "\x68\xb8\xa1");
    void* addr_cur = addr_start;
    while (addr_cur) 
    {
        addr_cur = winhook_searchmemory(addr_cur, (size_t)addr_end - (size_t)addr_cur, "68 75 81 00 00", NULL);
        if(!addr_cur) break;
        winhook_patchmemory(addr_cur, "\x68\xb8\xa1", 3);
        printf("patch at %p [68 b8 a1]\n", addr_cur);
    } 
    
    // 68 76 81 00 00 push 8176h
    addr_cur = addr_start;
    while (addr_cur) 
    {
        addr_cur = winhook_searchmemory(addr_cur, (size_t)addr_end - (size_t)addr_cur, "68 76 81 00 00", NULL);
        if(!addr_cur) break;
        winhook_patchmemory(addr_cur, "\x68\xb9\xa1", 3);
        printf("patch at %p [68 b9 a1]\n", addr_cur);
    } 

    // charset first byte table
    char *sjis_pattern = "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 02 02 02 02 02 02 02 02 02 02 02 02 02 02 02 02 02 02 02 02 02 02 02 02 02 02 02 02 02 02 02 02 02 02 02 02 02 02 02 02 02 02 02 02 02 02 02 02 02 02 02 02 02 02 02 02 02 02 02 02 02 02 02 00 02 03 03 03 03 03 03 03 03 03 03 03 03 03 03 03 03 03 03 03 03 03 03 03 03 03 03 03 03 03 03 03 02 02 02 02 02 02 02 02 02 02 02 02 02 02 02 02 02 02 02 02 02 02 02 02 02 02 02 02 02 02 02 02 02 02 02 02 02 02 02 02 02 02 02 02 02 02 02 02 02 02 02 02 02 02 02 02 02 02 02 02 02 02 02 02 03 03 03 03 03 03 03 03 03 03 03 03 03 03 03 03 03 03 03 03 03 03 03 03 03 03 03 03 03 00 00 00";
    char gbk_table[] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
        0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
        0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
        0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
        0x02, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, // 0x80
        0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
        0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
        0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, // 0xa0
        0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
        0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
        0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
        0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x00, 0x00, 0x00
    };
    addr_cur = addr_start;
    addr_cur = winhook_searchmemory(addr_cur, (size_t)addr_end - (size_t)addr_cur, sjis_pattern, NULL);
    if(addr_cur)
    {
        printf("patch at %p, gbk_table\n", addr_cur);
        winhook_patchmemory(addr_cur, gbk_table, sizeof(gbk_table));
    }
}

#endif

void install_hooks()
{
    // kernel32
    if(!winhook_iathook("Kernel32.dll", 
        GetProcAddress(GetModuleHandleA("Kernel32.dll"), 
        "CreateFileA"), (PROC)CreateFileA_hook))
    {
        printf("CreateFileA not fount!\n");
    }
    if(!winhook_iathook("Kernel32.dll", 
        GetProcAddress(GetModuleHandleA("Kernel32.dll"), 
        "CreateFileW"), (PROC)CreateFileW_hook))
    {
        printf("CreateFileW not fount!\n");
    }
    if(!winhook_iathook("Kernel32.dll", 
        GetProcAddress(GetModuleHandleA("Kernel32.dll"), 
        "GetACP"), (PROC)GetACP_hook))
    {
        printf("GetACP not fount!\n");
    }
    if(!winhook_iathook("Kernel32.dll", 
        GetProcAddress(GetModuleHandleA("Kernel32.dll"), 
        "GetCPInfo"), (PROC)GetCPInfo_hook))
    {
        printf("GetCPInfo not fount!\n");
    }

    if(!winhook_iathook("Kernel32.dll", 
        GetProcAddress(GetModuleHandleA("Kernel32.dll"), 
        "MultiByteToWideChar"), (PROC)MultiByteToWideChar_hook))
    {
        printf("MultiByteToWideChar not fount!\n");
    }
    if(!winhook_iathook("Kernel32.dll", 
        GetProcAddress(GetModuleHandleA("Kernel32.dll"), 
        "WideCharToMultiByte"), (PROC)WideCharToMultiByte_hook))
    {
        printf("WideCharToMultiByte not fount!\n");
    }

    // gdi32
    if(!winhook_iathook("Gdi32.dll", 
        GetProcAddress(GetModuleHandleA("Gdi32.dll"), 
        "CreateFontIndirectA"), (PROC)CreateFontIndirectA_hook))
    {
        printf("CreateFontA not fount!\n");
    }
    if(!winhook_iathook("Gdi32.dll", 
        GetProcAddress(GetModuleHandleA("Gdi32.dll"), 
        "EnumFontFamiliesA"), (PROC)EnumFontFamiliesA_hook))
    {
        printf("EnumFontFamiliesA not fount!\n");
    }

    if(g_majirocfg.patch_gbk) patch_gbk();
    winhook_patchmemorypattern(g_majirocfg.patch);
}

void install_console()
{
    AllocConsole();
    freopen("CONOUT$", "w", stdout);
    system("chcp 936");
    setlocale(LC_ALL, "chs");
    printf("majiro_patch v0.2, developed by devseed\n");
}

void read_config(const char *path)
{
    char tmp[MAX_PATH] = {0};
    char line[MAX_PATH] = {0};
    char *k = NULL;
    char *v = NULL;

    FILE *fp = fopen(path, "r");
    if(fp)
    {
        while(fgets(line, sizeof(line), fp))
        {
            k = strtok(line, "=\n");
            v = strtok(NULL, "=\n");
            printf("read config %s=%s\n", k, v);
            if(!_stricmp(k, "charset"))
            {
                g_majirocfg.charset = atoi(v);
            }
            else if(!_stricmp(k, "codepage"))
            {
                g_majirocfg.codepage = atoi(v);
            }
            else if(!_stricmp(k, "font"))
            {
                strcpy(g_majirocfg.font, v);
            }
            else if(!_stricmp(k, "patch"))
            {
                strcpy(g_majirocfg.patch, v);
            }
            else if(!_stricmp(k, "patch_gbk"))
            {
                g_majirocfg.patch_gbk = 1;
            }
        }
        fclose(fp);
    }
    else
    {
        printf("config %s not found!\n", path);
    }
}

__declspec(dllexport) void dummy()
{

}

BOOL WINAPI DllMain(
    HINSTANCE hinstDLL,  // handle to DLL module
    DWORD fdwReason,     // reason for calling function
    LPVOID lpReserved )  // reserved
{
    switch( fdwReason ) 
    { 
        case DLL_PROCESS_ATTACH:
#ifdef _DEBUG
            install_console();
#endif
            read_config(CONFIG_PATH);
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

/** history
 * v0.1, initial version, redirect file and patch
 * v0.1.1, add EnumFontFamiliesA_hook
 * v0.1.2, redirect savedata, as it is related to text modify
 * v0.1.3, add GetACP_hook, GetCPInfo_hook for other language os
 * v0.2, add automaticly search for patch gbk, support ルリのかさね ～いもうと物語り
*/