/**
 * majiro engine, localization support
 *   v0.1.2, developed by devseed
 * 
 * tested game:
 *   そらいろ (ねこねこソフト) v1.1
 *   (patch=+38C0:C3;+1903B:B8A1;+19087:B8A1;+19A7A:B8A1;+1905D:B9A1;+19AF0:B9A1)
 * 
 * override/config.ini // number must be decimal except patchpattern
 *   charset=128
 *   font=simhei
 *   patch=addr:bytes;...
*/

#include <stdio.h>
#include <windows.h>
#include <shlwapi.h>
#include <locale.h>

// winhook.h v0.3
#define WINHOOK_IMPLEMENTATION
#define MINHOOK_IMPLEMENTATION
#include "winhook.h"

// stb_image.h v2.27
#define STB_IMAGE_IMPLEMENTATION
#define STBI_NO_THREAD_LOCALS
#ifdef __TINYC__
#define STBI_NO_SIMD
#endif
#include "stb_image.h"

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
    char font[MAX_PATH];
    char patch[1024];
};

struct majirocfg_t g_majirocfg = 
{
    .charset=0x0, .font="\0",
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

int WINAPI MultiByteToWideChar_hook(
  UINT CodePage,
  DWORD  dwFlags,
  LPCCH lpMultiByteStr,
  int cbMultiByte,
  LPWSTR  lpWideCharStr,
  int cchWideChar)
{
    int ret = MultiByteToWideChar(CodePage, dwFlags, 
        lpMultiByteStr, cbMultiByte, lpWideCharStr, cchWideChar);
    printf("mbtowc %s\n", lpMultiByteStr);
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
    int ret = WideCharToMultiByte(CodePage, dwFlags, 
        lpWideCharStr, cchWideChar, 
        lpMultiByteStr, cbMultiByte, 
        lpDefaultChar, lpUsedDefaultChar);
    printf("wctmb %s\n", lpMultiByteStr);
    return ret;
}
#endif

#if 1 // inline hooks
#endif

void install_hooks()
{
    // iat hooks
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
    if(!winhook_iathook("Kernel32.dll", 
        GetProcAddress(GetModuleHandleA("Kernel32.dll"), 
        "CreateFileA"), (PROC)CreateFileA_hook))
    {
        printf("CreateFileA not fount!\n");
    }
#if 0
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
#endif

    winhook_patchmemorypattern(g_majirocfg.patch);
}

void install_console()
{
    AllocConsole();
    freopen("CONOUT$", "w", stdout);
    system("chcp 936");
    setlocale(LC_ALL, "chs");
    printf("majiro_patch v0.1.2, developed by devseed\n");
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
            else if(!_stricmp(k, "font"))
            {
                strcpy(g_majirocfg.font, v);
            }
            else if(!_stricmp(k, "patch"))
            {
                strcpy(g_majirocfg.patch, v);
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
*/