/**
 *  for AdvHD v1 and v2  
 *  translation support and redirect arc file
 *      v0.2.6, developed by devseed
 * 
 *  tested game: 
 *    あやかしごはん (v1.0.1.0)
 *    BlackishHouse (v1.6.2.1) 
 *    華は短し、踊れよ乙女 (1.9.9.9)
 *  
 *  override/config.ini, codepage charset
 *    codepage=932
 *    charset=128
 *    font=simhei // font name encoding is by codepage
 *    _ismbclegal=rva
 *    ucharmap=38021:9834, // '钅':'♪'
*/

#include <stdio.h>
#include <windows.h>
#include <shlwapi.h>
#include <locale.h>
#define WINHOOK_IMPLEMENTATION
#define WINHOOK_STATIC
#define MINHOOK_IMPLEMENTATION
#define MINHOOK_STATIC
#ifdef USECOMPAT
#include "stb_minhook_v1332.h"
#include "winhook_v330.h"
#else
#include "stb_minhook.h"
#include "winhook.h"
#endif

#define CONFIG_PATH "override\\config.ini"
#define REDIRECT_DIRA "override"
#define REDIRECT_DIRW L"override"
#define MAX_UCHARMAP 5
struct advhd_cfg_t
{
    char font[MAX_PATH];
    int codepage;
    int charset;
    UINT ucharmap[MAX_UCHARMAP][2];
};

static struct advhd_cfg_t g_advhdcfg = {
    .font="simhei", .codepage=936, .charset=GB2312_CHARSET, .ucharmap={0}
};

#if 1// advhd inline hooks
#define MAX_INLHOOK 3
static PVOID g_pfnTargets[MAX_INLHOOK] = {NULL};
static PVOID g_pfnNews[MAX_INLHOOK] = {NULL}; 
static PVOID g_pfnOlds[MAX_INLHOOK] = {NULL};
static HANDLE g_mutexs[MAX_INLHOOK] = {NULL};
#define CreateFileA_IDX 0
#define CreateFileW_IDX 1
#define _ismbclegal_IDX 2

typedef HANDLE (WINAPI *PFN_CreateFileA)(
    IN LPCSTR lpFileName,
    IN DWORD dwDesiredAccess,
    IN DWORD dwShareMode,
    IN OPTIONAL LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    IN DWORD dwCreationDisposition,
    IN DWORD dwFlagsAndAttributes,
    IN OPTIONAL HANDLE hTemplateFile);

typedef HANDLE (WINAPI *PFN_CreateFileW)(
    IN LPCWSTR lpFileName,
    IN DWORD dwDesiredAccess,
    IN DWORD dwShareMode,
    IN OPTIONAL LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    IN DWORD dwCreationDisposition,
    IN DWORD dwFlagsAndAttributes,
    IN OPTIONAL HANDLE hTemplateFile);

typedef DWORD (WINAPI *PFN_GetGlyphOutlineW_hook)(
  IN  HDC            hdc,
  IN  UINT           uChar,
  IN  UINT           fuFormat,
  OUT LPGLYPHMETRICS lpgm,
  IN  DWORD          cjBuffer,
  OUT LPVOID         pvBuffer,
  IN  const MAT2     *lpmat2);

static LPSTR _RedirectArcA(LPSTR lpFileName)
{
    static char tmppath[MAX_PATH] = {0};
    tmppath[0] = 0;
    char *name = PathFindFileNameA(lpFileName);
    if(name && (strstr(name, ".arc")||strstr(name, ".ARC")
    || strstr(name, ".dat")||strstr(name, ".DAT")))
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

static LPWSTR _RedirectArcW(LPWSTR lpFileName)
{
    static wchar_t tmppath[MAX_PATH] = {0};
    tmppath[0] = 0;
    wchar_t *name = PathFindFileNameW(lpFileName);
    if(name && (wcsstr(name, L".arc")||wcsstr(name, L".ARC")
    ||wcsstr(name, L".dat")||wcsstr(name, L".DAT")))
    {
        wcsncpy(tmppath, lpFileName, name - lpFileName);
        tmppath[name - lpFileName] = 0;
        wcscat(tmppath, REDIRECT_DIRW L"\\");
        wcscat(tmppath, name);
        if(PathFileExistsW(tmppath))
        {
            wprintf(L"CreateFileW redirect %ls -> %ls\n", lpFileName, tmppath);
            //wcscpy(lpFileName, tmppath);
            return tmppath;
        }
    }
    return NULL;
}

static HANDLE WINAPI CreateFileA_hook(
    IN LPSTR lpFileName,
    IN DWORD dwDesiredAccess,
    IN DWORD dwShareMode,
    IN OPTIONAL LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    IN DWORD dwCreationDisposition,
    IN DWORD dwFlagsAndAttributes,
    IN OPTIONAL HANDLE hTemplateFile)
{
    WaitForSingleObject(g_mutexs[CreateFileA_IDX], INFINITE);
    LPSTR targetpath = _RedirectArcA(lpFileName);
    if(!targetpath) targetpath = lpFileName;
    PFN_CreateFileA pfn = (PFN_CreateFileA)g_pfnOlds[CreateFileA_IDX];
    HANDLE res = pfn(targetpath, dwDesiredAccess, dwShareMode, 
        lpSecurityAttributes, dwCreationDisposition, 
        dwFlagsAndAttributes, hTemplateFile);
    ReleaseMutex(g_mutexs[CreateFileA_IDX]);
    return res;
}

static HANDLE WINAPI CreateFileW_hook(
    IN LPWSTR lpFileName,
    IN DWORD dwDesiredAccess,
    IN DWORD dwShareMode,
    IN OPTIONAL LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    IN DWORD dwCreationDisposition,
    IN DWORD dwFlagsAndAttributes,
    IN OPTIONAL HANDLE hTemplateFile)
{
    WaitForSingleObject(g_mutexs[CreateFileW_IDX], INFINITE);
    LPWSTR targetpath = _RedirectArcW(lpFileName);
    if(!targetpath) targetpath = lpFileName;
    PFN_CreateFileW pfn = (PFN_CreateFileW)g_pfnOlds[CreateFileW_IDX];
    HANDLE res = pfn(targetpath, dwDesiredAccess, dwShareMode, 
        lpSecurityAttributes, dwCreationDisposition, 
        dwFlagsAndAttributes, hTemplateFile);
    ReleaseMutex(g_mutexs[CreateFileW_IDX]);
    return res;
}

static int __cdecl _ismbclegal_hook(unsigned int c)
{
    int high = c>>8;
    int low = c&0xff;
    return (high >= 0x80) && (low >=0x40);
}
#endif

#if 1 // advhd v1 iat hooks
static LONG WINAPI RegOpenKeyExA_hook(HKEY hKey, 
    LPCSTR lpSubKey, DWORD ulOptions,
    DWORD samDesired, PHKEY phkResult)
{
    
    LONG status =  RegOpenKeyExA(
        hKey, lpSubKey, ulOptions, 
        samDesired, phkResult);
    if(status==ERROR_FILE_NOT_FOUND)
    {
        status = RegCreateKeyA(hKey, lpSubKey, phkResult);
        printf("RegOpenKeyExA %s\n create", lpSubKey);
    }
    return status;
}

static LONG WINAPI RegQueryValueExA_hook(HKEY hKey, 
    LPCSTR lpValueName, LPDWORD lpReserved, PDWORD lpType, 
    LPBYTE lpData, LPDWORD lpcbData)
{
    LONG status = RegQueryValueExA(
        hKey, lpValueName, lpReserved, 
        lpType, lpData, lpcbData);
    if(strstr(lpValueName, "InstallType"))
    {
        if(status==ERROR_FILE_NOT_FOUND)
        {
            
            *((DWORD*)lpData) = 0x2;
            status = ERROR_SUCCESS;
            printf("RegQueryValueExA %s, redirect to %lx\n", 
                lpValueName, *((DWORD*)lpData));
        }
    }
    else if(strstr(lpValueName, "InstallDir"))
    {
        *lpcbData = GetCurrentDirectoryA(MAX_PATH, (LPSTR)lpData);
        status = ERROR_SUCCESS;
        printf("RegQueryValueExA %s, redirect to %s\n", 
            lpValueName, (LPSTR)lpData);
    }
    return status;
}

static LCID WINAPI GetSystemDefaultLCID_hook(void)
{
    LCID lcid = GetSystemDefaultLCID();
    printf("GetSystemDefaultLCID %lx\n", lcid);
    return 0x411;
}

static HFONT WINAPI CreateFontIndirectA_hook(IN LOGFONTA *lplf)
{
    lplf->lfCharSet = g_advhdcfg.charset;
    strcpy(lplf->lfFaceName, g_advhdcfg.font);
    return CreateFontIndirectA(lplf);    
}
#endif

#if 1 // advhd v2 iat hooks
static int WINAPI MultiByteToWideChar_hook(
    IN UINT CodePage,
    IN DWORD dwFlags,
    IN LPCCH lpMultiByteStr,
    IN int cbMultiByte,
    OUT LPWSTR lpWideCharStr,
    IN int cchWideChar)
{
    UINT cp = g_advhdcfg.codepage;
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

static int WINAPI WideCharToMultiByte_hook(
    IN UINT CodePage,
    IN DWORD dwFlags,
    IN LPCWCH lpWideCharStr,
    IN int cchWideChar,
    OUT LPSTR lpMultiByteStr,
    IN int cbMultiByte,
    IN OPTIONAL LPCCH lpDefaultChar,
    OUT OPTIONAL LPBOOL lpUsedDefaultChar)
{
    int ret = WideCharToMultiByte(g_advhdcfg.codepage, dwFlags, 
        lpWideCharStr, cchWideChar, lpMultiByteStr, cbMultiByte, lpDefaultChar, lpUsedDefaultChar);
    // wprintf(L"wctmb %ls\n", lpWideCharStr);
    return ret;
}

static HFONT WINAPI CreateFontIndirectW_hook(IN LOGFONTW *lplf)
{
    lplf->lfCharSet = g_advhdcfg.charset;
    MultiByteToWideChar(g_advhdcfg.codepage, MB_COMPOSITE, g_advhdcfg.font, 
        strlen(g_advhdcfg.font) + 1, lplf->lfFaceName, sizeof(lplf->lfFaceName));
    return CreateFontIndirectW(lplf);
}

static DWORD WINAPI GetGlyphOutlineW_hook(
    IN  HDC            hdc,
    IN  UINT           uChar,
    IN  UINT           fuFormat,
    OUT LPGLYPHMETRICS lpgm,
    IN  DWORD          cjBuffer,
    OUT LPVOID         pvBuffer,
    IN  const MAT2     *lpmat2)
{
    UINT target_uchar = uChar;
    for(int i=0; g_advhdcfg.ucharmap[i][0]; i++)
    {
        if (uChar == g_advhdcfg.ucharmap[i][0])
        {
            target_uchar = g_advhdcfg.ucharmap[i][1];
            break;
        }
    }
    return GetGlyphOutlineW(hdc, target_uchar, fuFormat, lpgm, cjBuffer, pvBuffer, lpmat2);
}
#endif

static void install_inlinehooks()
{
    // get kernel32 or kernelbase
    PVOID kernel32 =  GetModuleHandleA("Kernelbase.dll");
    if(kernel32)
    {
        printf("using kernelbase.dll for inline hook\n");
    }
    else
    {   kernel32 = GetModuleHandleA("Kernel32.dll");
        printf("using kernel32.dll for inline hook\n");
    }

    // init each function
    g_pfnTargets[CreateFileA_IDX] =  (PVOID)GetProcAddress(kernel32, "CreateFileA"),
    g_pfnTargets[CreateFileW_IDX] =  (PVOID)GetProcAddress(kernel32, "CreateFileW"),
    g_pfnNews[CreateFileA_IDX] = (PVOID)CreateFileA_hook;
    g_pfnNews[CreateFileW_IDX] = (PVOID)CreateFileW_hook;
    g_pfnNews[_ismbclegal_IDX] = (PVOID)_ismbclegal_hook;
    g_mutexs[CreateFileA_IDX] = CreateMutexA(NULL, FALSE, NULL);
    g_mutexs[CreateFileW_IDX] = CreateMutexA(NULL, FALSE, NULL);

    // make inline hook
    MH_STATUS status = MH_Initialize();
    if(status!=MH_OK) LOGe("MH_Initialize %s\n", MH_StatusToString(status));
    int n = sizeof(g_pfnTargets)/sizeof(void*);
    for(int i=0; i< n; i++)
    {
        void *ptarget = g_pfnTargets[i];
        void *pnew = g_pfnNews[i];
        if(!ptarget) continue;
        status = MH_CreateHook(ptarget, pnew, &g_pfnOlds[i]);
        if(status!=MH_OK) LOGe("MH_CreateHook %d %p %s\n", i, ptarget, MH_StatusToString(status));
        status = MH_EnableHook(ptarget);
        if(status!=MH_OK)  LOGe("MH_EnableHook %d %p %s\n", i, ptarget, MH_StatusToString(status));
    }
}

static void install_iathooksv1()
{
    // advhd v1 hooks
    if(!winhook_iathook("Advapi32.dll", 
        GetProcAddress(GetModuleHandleA("Advapi32.dll"), 
        "RegOpenKeyExA"), (PROC)RegOpenKeyExA_hook))
    {
         printf("RegOpenKeyExA not fount!\n");
    }
    if(!winhook_iathook("Advapi32.dll", 
        GetProcAddress(GetModuleHandleA("Advapi32.dll"), 
        "RegQueryValueExA"), (PROC)RegQueryValueExA_hook))
    {
         printf("RegQueryValueExA not fount!\n");
    }
    if(!winhook_iathook("Kernel32.dll", 
        GetProcAddress(GetModuleHandleA("Kernel32.dll"), 
        "GetSystemDefaultLCID"), (PROC)GetSystemDefaultLCID_hook))
    {
        printf("GetSystemDefaultLCID not fount!\n");
    }
    if(!winhook_iathook("Gdi32.dll", 
        GetProcAddress(GetModuleHandleA("Gdi32.dll"), 
        "CreateFontIndirectA"), (PROC)CreateFontIndirectA_hook))
    {
        printf("CreateFontIndirectA not fount!\n");
    }
}

static void install_iathooksv2()
{
    // advhd v2 hooks
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
    if(!winhook_iathook("Gdi32.dll", 
        GetProcAddress(GetModuleHandleA("Gdi32.dll"), 
        "CreateFontIndirectW"), (PROC)CreateFontIndirectW_hook))
    {
        printf("CreateFontIndirectW not fount!\n");
    }
    if(!winhook_iathook("Gdi32.dll", 
        GetProcAddress(GetModuleHandleA("Gdi32.dll"), 
        "GetGlyphOutlineW"), (PROC)GetGlyphOutlineW_hook))
    {
        printf("GetGlyphOutlineW not fount!\n");
    }
}

static size_t get_imagesize(void *pe)
{
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pe;
    PIMAGE_NT_HEADERS  pNtHeader = (PIMAGE_NT_HEADERS)
        ((uint8_t*)pe + pDosHeader->e_lfanew);
    PIMAGE_FILE_HEADER pFileHeader = &pNtHeader->FileHeader;
    PIMAGE_OPTIONAL_HEADER pOptHeader = &pNtHeader->OptionalHeader;
    size_t imagesize = pOptHeader->SizeOfImage;
    return imagesize; 
}

static void read_config(const char *path)
{
    char line[MAX_PATH] = {0};
    char *k = NULL;
    char *v = NULL;

    // search _ismbclegal
    size_t base = (size_t)GetModuleHandleA(NULL);
    size_t imgsize = get_imagesize((void*)base);
    void* addr = winhook_searchmemory((void*)base, imgsize, 
        "55 8b ec 6a 00 ff 75 08 e8 aa ff ff ff 59 59 5d c3", NULL);
    if(addr) printf("find _ismbclegal at %p\n", addr);
    g_pfnTargets[_ismbclegal_IDX] = addr;
    
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
                g_advhdcfg.codepage = atoi(v);
            }
            else if(!_stricmp(k, "charset"))
            {
                g_advhdcfg.charset = atoi(v);
            }
            else if(!_stricmp(k, "font"))
            {
                strcpy(g_advhdcfg.font, v);
            }
            else if(!_stricmp(k, "_ismbclegal"))
            {
                size_t rva = (size_t)strtol(v, NULL, 16);
                g_pfnTargets[_ismbclegal_IDX] = (void*)(base+rva);
            }
            else if(!_stricmp(k, "ucharmap"))
            {
                int ucharmap_count = 0;
                char *entry = v;
                while(*entry)
                {
                    char *u1 = entry;
                    char *u2 = entry;
                    do { u2++; } while(*u2 != ':');
                    *u2 ++ = '\0';
                    entry = u2;
                    do { entry++; } while(*entry != ',' && *entry);
                    if(*entry==',') *entry++ = '\0';
                        
                    g_advhdcfg.ucharmap[ucharmap_count][0] = atoi(u1);
                    g_advhdcfg.ucharmap[ucharmap_count][1] = atoi(u2);
                    ucharmap_count ++; 
                }
            }
        }
        fclose(fp);
    }
    else
    {
        printf("config %s not found!\n", path);
    }
}

static void install_hooks()
{
    FILE *fp = fopen("advhd_patch_console", "rb");
    if(fp)
    {
        AllocConsole();
        system("chcp 936");
        setlocale(LC_ALL, "chs");
        wprintf(L"advhd v1v2 版本通用汉化补丁, build in 241024\n");
        freopen("CONOUT$", "w", stdout);
        fclose(fp);
    }
    printf("advhd_patch v0.2.6, developed by devseed\n");
    read_config(CONFIG_PATH);
    install_inlinehooks();
    install_iathooksv1();
    install_iathooksv2();
}

EXPORT void dummy()
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

/**
 * history
 * v0.1 support advhd.exe v2 version
 * v0.2 add support to advhd v1
 * V0.2.1 add config file for redirect
 * v0.2.2 add _ismbclegal hook and rva config for other codepage
 * v0.2.3, add automaticly search _ismbclegal
 * v0.2.4, add kernelbase createfile redirect, and mutex for multi thread
 * v0.2.5, update to winhook v0.3
 * v0.2.6, add redirect char to render some sjis char like
*/