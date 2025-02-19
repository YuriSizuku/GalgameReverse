/**
 * custom font support and file redirect for iwaihime, 
 *   v0.1, developed by devseed
 * 
 * usage:
 *   renmae the target dll to version.dll and put into game directory, 
 *   then it will read override/config.txt and replace files in override
 *   
 *   override/config.ini (must be in utf16-le with bom, unix lf)\
 *     charset=134
 *     exename=iw.exe
 *     # force use this fontname
 *     fontname=simhei
 *     # add user custom font
 *     fontpath=override/default.ttf
 * 
 * tested game:
 *   祝姫（steam） v1.0.2
 */

#include <stdio.h>
#include <stdint.h>
#include <shlwapi.h>
#include <windows.h>

#define MINHOOK_IMPLEMENTATION
#define MINHOOK_STATIC
#ifdef USECOMPAT
#include "winversion_v100.h"
#include "stb_minhook_v1332.h"
#else
#include "winversion.h"
#include "stb_minhook.h"
#endif

#define REDIRECT_DIR L"override"
#define DEFINE_HOOK(name) \
    t##name name##_org = NULL; \
    void *name##_old;

#define BIND_HOOK(name) \
    MH_CreateHook(name##_old, (LPVOID)(name##_hook), (LPVOID*)(&name##_org));\
    LOGi("BIND_HOOK " #name " %p -> %p\n", name##_old, name##_hook);\
    MH_EnableHook(name##_old)

#define UNBIND_HOOK(name) \
    if(name##_old) {\
        MH_DisableHook(name##_old); \
        LOGi("UNBIND_HOOK " #name " %p\n", name##_old); \
    }

typedef HANDLE (WINAPI *tCreateFileW)(
    IN LPCWSTR lpFileName,
    IN DWORD dwDesiredAccess,
    IN DWORD dwShareMode,
    IN OPTIONAL LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    IN DWORD dwCreationDisposition,
    IN DWORD dwFlagsAndAttributes,
    IN OPTIONAL HANDLE hTemplateFile);
typedef DWORD (WINAPI *tGetGlyphOutlineW)(
    IN  HDC            hdc,
    IN  UINT           uChar,
    IN  UINT           fuFormat,
    OUT LPGLYPHMETRICS lpgm,
    IN  DWORD          cjBuffer,
    OUT LPVOID         pvBuffer,
    IN  const MAT2     *lpmat2);
typedef HFONT (WINAPI *tCreateFontIndirectW)(const LOGFONTW *lplf);
typedef HFONT (WINAPI *tCreateFontW)(int cHeight,int cWidth,int cEscapement,int cOrientation,int cWeight,
    DWORD bItalic,DWORD bUnderline,DWORD bStrikeOut,DWORD iCharSet,
    DWORD iOutPrecision,DWORD iClipPrecision,
    DWORD iQuality,DWORD iPitchAndFamily,LPCWSTR pszFaceName);

struct iwaihime_cfg_t
{
    int charset;
    wchar_t exename[32];
    wchar_t fontname[32];
    wchar_t fontpath[MAX_PATH];
};

static struct iwaihime_cfg_t g_cfg = {
    .exename = L"*", .fontname=L"simhei", .fontpath = L"", .charset=0
};
DEFINE_HOOK(CreateFileW);
DEFINE_HOOK(CreateFontW);
DEFINE_HOOK(CreateFontIndirectW);
DEFINE_HOOK(GetGlyphOutlineW);

static LPWSTR _RedirectFileW(LPWSTR lpFileName)
{
    static wchar_t tmppath[MAX_PATH] = {0};
    tmppath[0] = 0;
    wchar_t *name = PathFindFileNameW(lpFileName);
    if(name && wcsstr(name, L".m"))
    {
        wcscpy(tmppath, REDIRECT_DIR L"\\");
        wcscat(tmppath, name);
        if(PathFileExistsW(tmppath))
        {
            LOGLi(L"REDIRECT %ls -> %ls\n", lpFileName, tmppath);
            // wcscpy(lpFileName, tmppath);
            return tmppath;
        }
    }
    return NULL;
}

HANDLE WINAPI CreateFileW_hook(
    IN LPCWSTR lpFileName,
    IN DWORD dwDesiredAccess,
    IN DWORD dwShareMode,
    IN OPTIONAL LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    IN DWORD dwCreationDisposition,
    IN DWORD dwFlagsAndAttributes,
    IN OPTIONAL HANDLE hTemplateFile)
{
    LPWSTR targetpath = _RedirectFileW((LPWSTR)lpFileName);
    if(!targetpath) targetpath = (LPWSTR)lpFileName;
    HANDLE res = CreateFileW_org(targetpath, dwDesiredAccess, dwShareMode, 
        lpSecurityAttributes, dwCreationDisposition, 
        dwFlagsAndAttributes, hTemplateFile);
    return res;
}

DWORD WINAPI GetGlyphOutlineW_hook(
    IN  HDC            hdc,
    IN  UINT           uChar,
    IN  UINT           fuFormat,
    OUT LPGLYPHMETRICS lpgm,
    IN  DWORD          cjBuffer,
    OUT LPVOID         pvBuffer,
    IN  const MAT2     *lpmat2)
{
    return GetGlyphOutlineW_org(hdc, uChar, fuFormat, lpgm, cjBuffer, pvBuffer, lpmat2);
}

HFONT WINAPI CreateFontIndirectW_hook(const LOGFONTW *lplf)
{
    if(wcslen(g_cfg.fontname))
    {
        LOGLi(L"facename %ls -> %ls\n", lplf->lfFaceName, g_cfg.fontname);
        wcscpy(((LOGFONTW *)(lplf))->lfFaceName, g_cfg.fontname);
    }
    if(g_cfg.charset)
    {
        ((LOGFONTW *)(lplf))->lfCharSet = g_cfg.charset;
    }
    return CreateFontIndirectW_org(lplf);
}

// the game use this function to create
HFONT WINAPI CreateFontW_hook(int cHeight, int cWidth, 
    int cEscapement, int cOrientation,int cWeight,
    DWORD bItalic,DWORD bUnderline,
    DWORD bStrikeOut,DWORD iCharSet,
    DWORD iOutPrecision,DWORD iClipPrecision,
    DWORD iQuality,DWORD iPitchAndFamily,LPCWSTR pszFaceName)
{
    static wchar_t tmpfont[32];
    if(wcslen(g_cfg.fontname))
    {
        LOGLi(L"facename %ls -> %ls\n", pszFaceName, g_cfg.fontname);
        wcscpy(tmpfont, g_cfg.fontname);
    }
    else
    {
        wcscpy(tmpfont, pszFaceName);
    }
    if(g_cfg.charset)
    {
        iCharSet = g_cfg.charset;
    }
    return CreateFontW_org(cHeight, cWidth, cEscapement, cOrientation, 
        cWeight, bItalic, bUnderline, bStrikeOut, iCharSet, 
        iOutPrecision, iClipPrecision, iQuality, iPitchAndFamily, tmpfont);
}

static void read_config(const char *path, struct iwaihime_cfg_t *cfg)
{
    FILE *fp = fopen(path, "rb");
    if(!fp)
    {
        LOGw("can not find %s", path);
        return;
    }
    
    wchar_t line[MAX_PATH] = {0};
    wchar_t *k = NULL;
    wchar_t *v = NULL;

    fread(line, 2, 1, fp);
    if(line[0] != 0xfeff) fseek(fp, 0, SEEK_SET);

    while(fgetws(line, sizeof(line)/2, fp))
    {
        k = wcstok(line, L"=\n");
        v = wcstok(NULL, L"=\n");
        LOGLi(L"read config %ls=%ls\n", k, v);
        if(!_wcsicmp(k, L"exename"))
        {
            wcscpy(cfg->exename, v);
        }
        else if(!_wcsicmp(k, L"fontname"))
        {
            wcscpy(cfg->fontname, v);
        }
        else if(!_wcsicmp(k, L"fontpath")) // user custome font
        {
            wcscpy(cfg->fontpath, v);
        }
        else if(!_wcsicmp(k, L"charset")) // user custome font
        {
            cfg->charset = _wtoi(v);
        }
    }
    fclose(fp);
}

static void print_info()
{
    printf("iwaihime_patch, v0.1, developed by devseed\n");
    
    DWORD winver = GetVersion();
    DWORD winver_major = (DWORD)(LOBYTE(LOWORD(winver)));
    DWORD winver_minor = (DWORD)(HIBYTE(LOWORD(winver)));
    LOGi("version NT=%lu.%lu\n", winver_major, winver_minor);
    #if defined(_MSC_VER)
    LOGi("compiler MSVC=%d\n", _MSC_VER)
    #elif defined(__GNUC__)
    LOGi("compiler GNUC=%d.%d\n", __GNUC__, __GNUC_MINOR__);
    #elif defined(__TINYC__)
    LOGi("compiler TCC\n");
    #endif
}

static void init()
{
    // load config
    FILE *fp = fopen("DEBUG_CONSOLE", "rb");
    if(fp)
    {
        AllocConsole();
        freopen("CONOUT$", "w", stdout); // problem on printf wchar_t with kanji
    }
    print_info();
    read_config("override/config.ini", &g_cfg);

    // check exe
    MH_STATUS status = MH_Initialize();
    if(status != MH_OK)
    {
        LOGe("MH_Initialize failed with %s\n", MH_StatusToString(status));
        return;
    }
    wchar_t modname[MAX_PATH];
    GetModuleFileNameW(NULL, modname, MAX_PATH);
    if(wcsstr(g_cfg.exename, L"*") == NULL && wcsstr(modname, g_cfg.exename) == NULL)
    {
        LOGLw(L"current exe is not the target %ls, will skip\n", g_cfg.exename);
        return;
    }

    // get kernel32 or kernelbase
    PVOID kernel32 =  GetModuleHandleA("Kernelbase.dll");
    if(kernel32)
    {
        LOGi("using kernelbase.dll for inline hook\n");
    }
    else
    {   kernel32 = GetModuleHandleA("Kernel32.dll");
        LOGi("using kernel32.dll for inline hook\n");
    }
    PVOID gdi32 = GetModuleHandleA("Gdi32.dll");

    // hook font
    CreateFileW_old = GetProcAddress(kernel32, "CreateFileW");
    BIND_HOOK(CreateFileW);

    if(wcslen(g_cfg.fontname) > 0)
    {
        CreateFontIndirectW_old = GetProcAddress(gdi32, "CreateFontIndirectW");
        BIND_HOOK(CreateFontIndirectW);
        CreateFontW_old = GetProcAddress(gdi32, "CreateFontW");
        BIND_HOOK(CreateFontW);
    }
    if(wcslen(g_cfg.fontpath) > 0)
    {
        int res = AddFontResourceW(g_cfg.fontpath);
        LOGLi(L"AddFontResourceW %ls res=%d\n", g_cfg.fontpath, res);
    }
}

static void uninit()
{
    if(wcslen(g_cfg.fontpath) > 0)
    {
        RemoveFontResourceW(g_cfg.fontpath);
    }

    MH_STATUS status = MH_Uninitialize();
    if(status != MH_OK)
    {
        LOGe("MH_Initialize failed with %s\n", MH_StatusToString(status));
    }
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL,  DWORD fdwReason,  LPVOID lpReserved)
{
    switch(fdwReason) 
    { 
        case DLL_PROCESS_ATTACH:
            winversion_init();
            init();
            break;
        case DLL_THREAD_ATTACH:
            break;
        case DLL_THREAD_DETACH:
            break;
        case DLL_PROCESS_DETACH:
            uninit();
            break;
    }
    return TRUE;
}