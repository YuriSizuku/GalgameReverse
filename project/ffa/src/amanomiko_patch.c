/**
 *  for G1WIN.EXE (天巫女姫) chs support
 *  v0.1.1, developed by devseed
 *  
*/

#include <stdio.h>
#include <stdint.h>
#include <windows.h>
#include <mbctype.h>

// lzss v1.0
#define LZSS_IMPLEMENTATION
#define LZSS_DECINITBYTE 0x20
#ifdef USE_COMPAT
#include "lzss_v1000.h"
#else
#include "lzss.h"
#endif

#ifdef USE_DVFS
#define WINDVFS_IMPLEMENTATION
#ifdef USE_COMPAT
#include "dvfs/windvfs_v301.h"
#else
#include "windvfs.h"
#endif
#else
#define WINHOOK_IMPLEMENTATION
#include "winhook_v310.h"
#endif

struct ffalzss_t{
    uint32_t zsize;
    uint32_t rawsize;
    char data[1];
};

PVOID g_pfnTargets[];
PVOID g_pfnNews[];
PVOID g_pfnOlds[];

HFONT WINAPI CreateFontIndirectA_hook(LOGFONTA *lplf)
{
    lplf->lfCharSet = GB2312_CHARSET;
    strcpy(lplf->lfFaceName, "simhei");
    return CreateFontIndirectA(lplf);
}

int WINAPI WideCharToMultiByte_hook(UINT CodePage, DWORD dwFlags,
    LPCWCH lpWideCharStr, int cchWideChar, LPSTR lpMultiByteStr,
    int cbMultiByte, LPCCH lpDefaultChar, LPBOOL lpUsedDefaultChar
)
{
    CodePage=936;
    return WideCharToMultiByte(CodePage, dwFlags, 
        lpWideCharStr, cchWideChar, lpMultiByteStr, 
        cbMultiByte, lpDefaultChar, lpUsedDefaultChar);
}

int WINAPI MultiByteToWideChar_hook(
	UINT CodePage, DWORD dwFlags,
	LPCCH lpMultiByteStr, int cbMultiByte,
	LPWSTR lpWideCharStr, int cchWideChar
)
{
    CodePage=936;
    return MultiByteToWideChar(CodePage, dwFlags, 
        lpMultiByteStr, cbMultiByte, 
        lpWideCharStr, cchWideChar);
}

int __cdecl _ismbblead_hook(unsigned int Ch)
{
    // typedef int (*PFN_ismbblead)(unsigned int Ch);
    // PFN_ismbblead pfn_ismbblead = (PFN_ismbblead)g_pfnOlds[1];
    // return pfn_ismbblead(Ch);
    if(Ch > 0x80) return 1;
    else return 0; 
}

int __cdecl _setmbcp_hook(int CodePage)
{
    typedef int (*PFN_setmbcp)(int CodePage);
    PFN_setmbcp pfn_setmbcp = (PFN_setmbcp)g_pfnOlds[2];
    CodePage = 936;
    return pfn_setmbcp(CodePage);
}

int __cdecl decodelzss_44850C_hook(
    char *compressed_buf, char *raw_buf, int default_return)
{
    struct ffalzss_t* ffalzss = (struct ffalzss_t*)compressed_buf;
    // dirty fix for hcg loading
    if(0)
    {
        typedef int (*PFN_decodelzss)(char*, char*, int);
        PFN_decodelzss pfn_deocdelzss = g_pfnOlds[0];
        return pfn_deocdelzss(compressed_buf, raw_buf, default_return);
    }

    uint32_t* pdword_45B910 = (uint32_t*)0x45B910;
    uint32_t* pdword_45B914 = (uint32_t*)0x45B914;
    uint32_t* pdword_45B920 = (uint32_t*)0x45B920;
    *pdword_45B910 = (uint32_t)compressed_buf;
    *pdword_45B914 = (uint32_t)raw_buf;
    *pdword_45B920 = (uint32_t)default_return;    
    lzss_decode(ffalzss->data, raw_buf, ffalzss->zsize);
    return default_return;
}

void install_fonthook()
{   
    // hook CreateFontIndirectA
    if(!winhook_iathook("gdi32.dll", GetProcAddress(
        GetModuleHandleA("gdi32.dll"), "CreateFontIndirectA"), 
        (PROC)CreateFontIndirectA_hook))
    {
        MessageBoxA(0, "CreateFontIndirectA hook error", "IAThook error", 0);
    }
}

// 0x4226A0
extern int __cdecl check_RegKey_hook(const char* key);
// 0x422510
extern int __cdecl get_reg_value_hook(const char* key, char* lpData);
// 0x444590
extern LRESULT CALLBACK WndProc_Hook(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam);
// 0x41BDA0
extern int __cdecl DrawText_Hook(HDC hdc, const char* text, int count, int extra, int, int, int);
// 0x41A7A4
extern void DrawTextSingle_Hook(void);
// 0x42D3EA
extern void AddFontManagerMenu(void);
// 0x42D576
extern void FixCheckMenuItemIndex(void);

PVOID g_pfnTargets[] = {
    (PVOID)0x44850C, 
    (PVOID)0x44BD90, 
    (PVOID)0x44B9B0,
    (PVOID)0x4226A0,
    (PVOID)0x422510,
    (PVOID)0x444590,
    (PVOID)0x41A7A4,
    (PVOID)0x42D3EA,
    (PVOID)0x41BDA0,
    (PVOID)0x42D576 };
PVOID g_pfnNews[] = {
    (PVOID)decodelzss_44850C_hook, 
    (PVOID)_ismbblead_hook,
    (PVOID)_setmbcp_hook,
    (PVOID)check_RegKey_hook,
    (PVOID)get_reg_value_hook,
    (PVOID)WndProc_Hook,
    (PVOID)DrawTextSingle_Hook,
    (PVOID)AddFontManagerMenu,
    (PVOID)DrawText_Hook,
    (PVOID)FixCheckMenuItemIndex };
PVOID g_pfnOlds[sizeof(g_pfnTargets)/sizeof(PVOID)];

void install_hooks()
{
    #ifdef _DEBUG
    AllocConsole();
    freopen("CONOUT$", "w", stdout);
    #if defined(PROJECT_NAME) && defined(PROJECT_VERSION) && defined(PROJECT_BUILD_TIME)
        printf("install hook " PROJECT_NAME ", v" PROJECT_VERSION ", build in " PROJECT_BUILD_TIME ".\n\n");
    #else
        printf("install hook, v0.1.1, build in 220702\n");
    #endif
    #endif
    install_fonthook();
    winhook_inlinehooks(
        g_pfnTargets, g_pfnNews, g_pfnOlds, 
        sizeof(g_pfnTargets)/sizeof(PVOID));
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
#ifdef USE_DVFS
            windvfs_install();
#endif
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

/*
 *  history
 *  v0.1, support amanomiko new version lzss and gbk
 *  v0.1.1, fix hcg with lzss format
*/