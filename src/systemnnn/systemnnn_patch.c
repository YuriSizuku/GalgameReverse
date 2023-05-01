/**
 * translation support and redirect arc file
 * for systemNNN engine
 *   v0.1, developed by devseed
 * 
 * tested game: 
 *   倭人異聞録～あさき、ゆめみし～ (+3DC17:FE)
 *  
 * override/config.ini, codepage charset
 *   codepage=932
 *   charset=128
 *   font=simhei
 *   patch=wajin_asaki.patch 
*/

#include <stdio.h>
#include <windows.h>
#include <shlwapi.h>
#include <locale.h>

// winhook v0.3
#define WINHOOK_IMPLEMENTATION
#include "winhook.h"

#define CONFIG_PATH "override\\config.ini"
#define REDIRECT_DIRA "override"
#define REDIRECT_DIRW L"override"
char g_font[MAX_PATH] = "simhei";
char g_patchpattern[1024] = {0};
int g_codepage = 936;
int g_charset = GB2312_CHARSET;

#if 1 // iat hooks
LPSTR _RedirectFileA(LPSTR lpFileName)
{
    static char tmppath[MAX_PATH] = {0};
    tmppath[0] = 0;
    strcat(tmppath, REDIRECT_DIRA "\\");
    strcat(tmppath, lpFileName);
    if(PathFileExistsA(tmppath))
    {
        printf("CreateFileA redirect %s -> %s\n", lpFileName, tmppath);
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

int WINAPI MultiByteToWideChar_hook(
    IN UINT CodePage,
    IN DWORD dwFlags,
    IN LPCCH lpMultiByteStr,
    IN int cbMultiByte,
    OUT LPWSTR lpWideCharStr,
    IN int cchWideChar)
{
    UINT cp = g_codepage;
    // printf("mbtwc %s\n", lpMultiByteStr);
    int ret = MultiByteToWideChar(cp, dwFlags, 
        lpMultiByteStr, cbMultiByte, 
        lpWideCharStr, cchWideChar);
    // wprintf(L"mbtwc %ls\n", lpWideCharStr);
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
    int ret = WideCharToMultiByte(g_codepage, dwFlags, 
        lpWideCharStr, cchWideChar, 
        lpMultiByteStr, cbMultiByte, 
        lpDefaultChar, lpUsedDefaultChar);
    // wprintf(L"wctmb %ls\n", lpWideCharStr);
    return ret;
}

HFONT WINAPI CreateFontA_hook(int cHeight, int cWidth, 
    int cEscapement, int cOrientation, int cWeight, DWORD bItalic,
    DWORD bUnderline, DWORD bStrikeOut, DWORD iCharSet,  
    DWORD iOutPrecision, DWORD iClipPrecision,
    DWORD iQuality, DWORD iPitchAndFamily, LPCSTR pszFaceName)
{
    return CreateFontA(cHeight, cWidth, 
        cEscapement, cOrientation, cWeight, bItalic, 
        bUnderline, bStrikeOut, g_charset, 
        iOutPrecision, iClipPrecision, 
        iQuality, iPitchAndFamily, g_font);
}

#endif

void install_hooks()
{
    if(!winhook_iathook("Gdi32.dll", 
        GetProcAddress(GetModuleHandleA("Gdi32.dll"), 
        "CreateFontA"), (PROC)CreateFontA_hook))
    {
        printf("CreateFontA not fount!\n");
    }
    if(!winhook_iathook("Kernel32.dll", 
        GetProcAddress(GetModuleHandleA("Kernel32.dll"), 
        "CreateFileA"), (PROC)CreateFileA_hook))
    {
        printf("CreateFileA not fount!\n");
    }

    // some patch like sjis check, like wajin_asaki, change A0 to FE
    // 0043DC11 | 81BD ACFEFFFF A0000000 | cmp dword ptr ss:[ebp-154],A0
    winhook_patchmemorypattern(g_patchpattern);
}

void install_console()
{
    AllocConsole();
    freopen("CONOUT$", "w", stdout);
    system("chcp 936");
    setlocale(LC_ALL, "chs");
    printf("systemnnn_patch v0.1, developed by devseed\n");
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
            if(!_stricmp(k, "codepage"))
            {
                g_codepage = atoi(v);
            }
            else if(!_stricmp(k, "charset"))
            {
                g_charset = atoi(v);
            }
            else if(!_stricmp(k, "font"))
            {
                strcpy(g_font, v);
            }
            else if(!_stricmp(k, "patch"))
            {
                sprintf(tmp, "%s\\%s", REDIRECT_DIRA, v);
                FILE *fp = fopen(tmp, "rb");
                fseek(fp, 0, SEEK_END);
                size_t fsize = ftell(fp);
                fseek(fp, 0, SEEK_SET);
                fread(g_patchpattern, 1, fsize, fp);
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

/* history
* v0.1, support advhd.exe v2 version
*/