/**
 *  redirect files to unencrypted xp3 file
 *   v0.2, developed by devseed
 * 
 * build:
 *   clang++ -m32 -shared -Wno-null-dereference -Isrc/compat -DUSECOMPAT src/krkr_hxv4_patch.cpp src/compat/tp_stub.cpp src/compat/winversion_v100.def -lgdi32 -o asset/build/version.dll -g -gcodeview -Wl,--pdb=asset/build/version.pdb 
 * 
 * usage:
 *   renmae the target dll to version.dll and put into game directory, 
 *   then it will read override/config.txt and replace files in override/patch.xp3
 *   
 *   override/config.ini (must be in utf16-le with bom, unix lf)
 *     loglevel=2
 *     exename=DC5PH_chs.exe
 *     xp3path=override/patch.xp3
 *     charset=134
 *     # force use this fontname
 *     fontname=simhei
 *     # add user custom font
 *     fontpath=override/default.ttf
 * 
 * tested games:
 *   D.C.5 Plus Happiness ～ダ・カーポ5～プラスハピネス // arc://./
 *   GINKA // arc://./
 *   Atri: My Dear Moments // archive://(.+?)/.xp3/...
 * 
 * refer: 
 *   https://github.com/crskycode/KrkrDump/blob/master/KrkrDump/dllmain.cpp
 */

#include <cstdio>
#include <cstdint>
#include <string>
#include <clocale>
#include <windows.h>
#include "tp_stub.h"

#define WINHOOK_IMPLEMENTATION
#define WINHOOK_NOINLINE
#define WINHOOK_STATIC 
#define MINHOOK_IMPLEMENTATION
#define MINHOOK_STATIC
#ifdef USECOMPAT
#include "winhook_v350.h"
#include "winversion_v100.h"
#include "stb_minhook_v1332.h"
#else
#include "winhook.h"
#include "winversion.h"
#include "stb_minhook.h"
#endif

#define DEFINE_HOOK(name) \
    decltype(name##_hook) *name##_org = nullptr; \
    void *name##_old;

#define DEFINE_SIG(name, sig) \
    const char *name##_sig = static_cast<const char *>(sig);

#define BIND_HOOK(name) \
    MH_CreateHook(name##_old, reinterpret_cast<LPVOID>(name##_hook), reinterpret_cast<LPVOID*>(&name##_org));\
    LOGi("BIND_HOOK " #name " %p -> %p\n", name##_old, name##_hook);\
    MH_EnableHook(name##_old)

#define UNBIND_HOOK(name) \
    if(name##_old) {\
        MH_DisableHook(name##_old); \
        LOGi("UNBIND_HOOK " #name " %p\n", name##_old); \
    }

static const char* ucs2utf8(const wchar_t * format, ...)
{
    static char tmp[1024*3];
    static wchar_t tmpw[1024];

    va_list arglist;
    va_start(arglist, format);
    vswprintf(tmpw, format, arglist);
    va_end(arglist);
    int n = WideCharToMultiByte(CP_UTF8, 0, tmpw, wcslen(tmpw), tmp, sizeof(tmp), NULL, NULL);
    tmp[n] = '\0';
    
    return tmp;
}

// struct and functino
struct krkrpatch_cfg_t
{
    int charset;
    int loglevel;
    std::wstring exename;
    std::wstring xp3path;
    std::wstring fontname;
    std::wstring fontpath;
};
static HRESULT __stdcall V2Link_hook(iTVPFunctionExporter* exporter);
static tTJSBinaryStream* FASTCALL TVPCreateStream_hook(ttstr* name, tjs_uint32 flags);
static FARPROC WINAPI GetProcAddress_hook(HMODULE hModule, LPCSTR lpProcName);
static int WINAPI EnumFontFamiliesExW_hook(HDC hdc, LPLOGFONTW lpLogfont, 
    FONTENUMPROCW lpProc, LPARAM lParam, DWORD dwFlags
);
HFONT WINAPI CreateFontIndirectW_hook(const LOGFONTW *lplf);

// global value define
#define CONFIG_PATH "override/config.ini"
static struct krkrpatch_cfg_t g_cfg = {
    .charset=0,.loglevel=1, 
    .exename=L"*", .xp3path=L"override/patch.xp3",
    .fontname=L"", .fontpath=L""
};
iTVPFunctionExporter *g_exporter = nullptr;
FONTENUMPROCW g_fontproc = nullptr;
DEFINE_HOOK(TVPCreateStream);
DEFINE_HOOK(V2Link);
DEFINE_HOOK(GetProcAddress);
DEFINE_HOOK(EnumFontFamiliesExW);
DEFINE_HOOK(CreateFontIndirectW);
DEFINE_SIG(TVPCreateStream, "55 8b ec 6a ff 68 ? ? ? ? 64 a1 ? ? ? ? 50 83 ec 5c 53 56 57 a1 ? ? ? ? 33 c5 50 8d 45 f4 64 a3 ? ? ? ? 89 65 f0 89 4d ec c7 45 ? ? ? ? ? e8 ? ? ? ? 8b 4d f4 64 89 0d ? ? ? ? 59 5f 5e 5b 8b e5 5d c3");

// hook functions
HRESULT __stdcall V2Link_hook(iTVPFunctionExporter* exporter)
{
    LOGi("exporter %p\n", exporter);
    TVPInitImportStub(exporter); // must bind exporter here
    g_exporter = exporter;
    UNBIND_HOOK(V2Link);
    return V2Link_org(exporter);
}

tTJSBinaryStream* FASTCALL TVPCreateStream_hook(ttstr* name, tjs_uint32 flags)
{
    if(!g_exporter) return TVPCreateStream_org(name, flags);
    if(flags != TJS_BS_READ) return TVPCreateStream_org(name, flags);
    
    const wchar_t *inpath = static_cast<const wchar_t*>(name->c_str());
    if(wcsstr(inpath, L"arc://")) // hxv4
    {
        const wchar_t *inname = inpath + 6;
        if(wcsncmp(inname, L"./", 2) ==0) inname += 2;
        ttstr name_redirct = g_cfg.xp3path.c_str() + ttstr(">") + ttstr(inname);
        ttstr name_full = TVPGetAppPath() + L"/" + name_redirct;
        if (TVPIsExistentStorageNoSearchNoNormalize(name_full))
        {
            if(g_cfg.loglevel >= 1)  LOGi("%s\n", ucs2utf8(L"REDIRECT %ls -> %ls", name->c_str(), name_redirct.c_str()));
            return TVPCreateStream_org(&name_full, flags);
        }
        else
        {
            if(g_cfg.loglevel >= 2) LOGi("NOREDIRECT %s\n", ucs2utf8(inpath));
        }
    }
    else if(wcsstr(inpath, L"archive://")) // older cx
    {
        const wchar_t *inname = wcsstr(inpath, L".xp3/");
        if(inname)
        {
            inname += 5;
            ttstr name_redirct = g_cfg.xp3path.c_str() + ttstr(">") + ttstr(inname);
            ttstr name_full = TVPGetAppPath() + L"/" + name_redirct;
            if (TVPIsExistentStorageNoSearchNoNormalize(name_full))
            {
                if(g_cfg.loglevel >= 1)  LOGi("%s\n", ucs2utf8(
                        L"REDIRECT %ls -> %ls", name->c_str(), name_redirct.c_str()));
                return TVPCreateStream_org(&name_full, flags);
            }
            else
            {
                if(g_cfg.loglevel >= 2) LOGi("NOREDIRECT %s\n", ucs2utf8(inpath));
            }
        }
        else
        {
            if(g_cfg.loglevel >= 2) LOGi("NOREDIRECT %s\n", ucs2utf8(inpath));
        }
    }
    if(g_cfg.loglevel >= 2) LOGi("OTHER %s\n", ucs2utf8(inpath));
    return TVPCreateStream_org(name, flags);
}

FARPROC WINAPI GetProcAddress_hook(HMODULE hModule, LPCSTR lpProcName)
{
    auto res = GetProcAddress_org(hModule, lpProcName);
    if(strcmp(lpProcName, "V2Link")==0)
    {
        V2Link_old = reinterpret_cast<void*>(res);
        BIND_HOOK(V2Link);
        UNBIND_HOOK(GetProcAddress);
    }
    return res;
}

BOOL CALLBACK fontproc_hook(CONST LOGFONTW *lplf,CONST TEXTMETRICW *lpntm,DWORD FontType,LPARAM lParam) 
{
    if(g_cfg.charset) 
    {
        ((LOGFONTW *)(lplf))->lfCharSet = g_cfg.charset;
        if(g_cfg.loglevel >= 3) LOGi("charset %x -> %x\n", lplf->lfCharSet, g_cfg.charset);
    }
    if(g_fontproc) return g_fontproc(lplf, lpntm, FontType, lParam);
    return FALSE;
}

int WINAPI EnumFontFamiliesExW_hook(HDC hdc, LPLOGFONTW lpLogfont, 
    FONTENUMPROCW lpProc, LPARAM lParam, DWORD dwFlags
)
{
    g_fontproc = lpProc;
    return EnumFontFamiliesExW_org(hdc, lpLogfont, fontproc_hook, lParam, dwFlags);
}

HFONT WINAPI CreateFontIndirectW_hook(const LOGFONTW *lplf)
{
    if(g_cfg.charset) 
    {
        if(g_cfg.loglevel >= 3) LOGi("charset %x -> %x\n", lplf->lfCharSet, g_cfg.charset);
        ((LOGFONTW *)(lplf))->lfCharSet = g_cfg.charset;
    }
    if(g_cfg.fontname.length() > 0) 
    {
        if(g_cfg.loglevel >= 3) LOGLi(L"facename %ls -> %ls\n", lplf->lfFaceName, g_cfg.fontname.c_str());
        wcscpy(((LOGFONTW *)(lplf))->lfFaceName, g_cfg.fontname.c_str());
    }
    return CreateFontIndirectW_org(lplf);
}

// other functions
static void read_config(const char *path, struct krkrpatch_cfg_t *cfg)
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
            cfg->exename = std::wstring(v);
        }
        else if(!_wcsicmp(k, L"xp3path"))
        {
            cfg->xp3path = std::wstring(v);
        }
        else if(!_wcsicmp(k, L"charset"))
        {
            cfg->charset = _wtoi(v);
        }
        else if(!_wcsicmp(k, L"fontname"))
        {
            cfg->fontname = std::wstring(v);
        }
        else if(!_wcsicmp(k, L"fontpath")) // user custome font
        {
            cfg->fontpath = std::wstring(v);
        }
        else if(!_wcsicmp(k, L"loglevel"))
        {
            cfg->loglevel = _wtoi(v);
        }
    }

    fclose(fp);
}

static void print_info()
{
    printf("krkr_hxv4_patch, v0.2, developed by devseed\n");
    
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
    read_config(CONFIG_PATH, &g_cfg);

    // check exe
    auto status = MH_Initialize();
    if(status != MH_OK)
    {
        LOGe("MH_Initialize failed with %s\n", MH_StatusToString(status));
        return;
    }
    wchar_t modname[MAX_PATH];
    GetModuleFileNameW(NULL, modname, MAX_PATH);
    if(g_cfg.exename.find(L"*") == std::wstring::npos && 
        wcsstr(modname, g_cfg.exename.c_str()) == nullptr)
    {
        LOGLw(L"current exe is not the target %ls, will skip\n", g_cfg.exename.c_str());
        return;
    }

    // hook stream
    GetProcAddress_old = reinterpret_cast<void*>(GetProcAddress);
    BIND_HOOK(GetProcAddress);
    size_t imagebase = winhook_getimagebase(GetCurrentProcess());
    size_t imagesize = winhook_getimagesize(GetCurrentProcess(), (HMODULE)imagebase);
    TVPCreateStream_old = winhook_searchmemory(
        (void*)imagebase, imagesize, TVPCreateStream_sig, NULL);
    BIND_HOOK(TVPCreateStream);

    // hook font
    if(g_cfg.charset)
    {
        EnumFontFamiliesExW_old = reinterpret_cast<void*>(EnumFontFamiliesExW);
        BIND_HOOK(EnumFontFamiliesExW);
    }
    if(g_cfg.fontname.length() > 0)
    {
        CreateFontIndirectW_old = reinterpret_cast<void*>(CreateFontIndirectW);
        BIND_HOOK(CreateFontIndirectW);
    }
    if(g_cfg.fontpath.length() > 0)
    {
        int res = AddFontResourceW(g_cfg.fontpath.c_str());
        LOGLi(L"AddFontResourceW %ls res=%d\n", g_cfg.fontpath.c_str(), res);
    }
}

static void uninit()
{
    if(g_cfg.fontpath.length() > 0)
    {
        RemoveFontResourceW(g_cfg.fontpath.c_str());
    }
    auto status = MH_Uninitialize();
    if(status != MH_OK)
    {
        LOGe("MH_Initialize failed with %s\n", MH_StatusToString(status));
    }
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL,  DWORD fdwReason,  LPVOID lpReserved )
{
    switch( fdwReason ) 
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

/**
 * history
 *   v0.1, initial version support hxv4
 *   v0.1.1, change some parameters
 *   v0.2, support older cx archive://, such as atri
 */