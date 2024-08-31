/**
 * systemNNN engine 
 * localization support, redirect file, loadpng in dib
 *   v0.2.1, developed by devseed
 * 
 * tested game: 
 *   倭人異聞録～あさき、ゆめみし～ 
 *   (patch=+3DC17:FE;CPicture_LoadDWQ=;CPicture_mpic=32)
 *  
 * override/config.ini // number must be decimal except patchpattern
 *   charset=128
 *   font=simhei
 *   patchpattern=wajin_asaki.patch
 *   CPicture_LoadDWQ=rva
 *   CPicture_mpic=offset
*/

#include <stdio.h>
#include <windows.h>
#include <shlwapi.h>
#include <locale.h>

// winhook.h v0.3
#define WINHOOK_IMPLEMENTATION
#define MINHOOK_IMPLEMENTATION
#ifdef USE_COMPAT
#include "winhook_v310.h"
#else
#include "winhook.h"
#endif

// stb_image.h v2.27
#define STB_IMAGE_IMPLEMENTATION
#define STBI_NO_THREAD_LOCALS
#ifdef __TINYC__
#define STBI_NO_SIMD 
#endif
#ifdef USE_COMPAT
#include "stb_image_v2270.h"
#else
#include "stb_image.h"
#endif

#define CONFIG_PATH "override\\config.ini"
#define REDIRECT_DIRA "override"
#define REDIRECT_DIRW L"override"

#define CPicture_LoadDWQ_IDX 0
PVOID g_pfnTargets[1] = {NULL};
PVOID g_pfnNews[1] = {NULL}; 
PVOID g_pfnOlds[1] = {NULL};
HANDLE g_mutexs[1] = {NULL};

struct systemnnn_cfg_t{
    int charset;
    char font[MAX_PATH];
    char patch[1024];
    size_t CPicture_LoadDWQ; // addr
    size_t CPicture_mpic; // offset
};

struct systemnnn_cfg_t g_systemnnncfg = 
{
    .charset=936, .font="simehei",
    .patch={0}, .CPicture_LoadDWQ=0, .CPicture_mpic=32,
};

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

HFONT WINAPI CreateFontA_hook(int cHeight, int cWidth, 
    int cEscapement, int cOrientation, int cWeight, DWORD bItalic,
    DWORD bUnderline, DWORD bStrikeOut, DWORD iCharSet,  
    DWORD iOutPrecision, DWORD iClipPrecision,
    DWORD iQuality, DWORD iPitchAndFamily, LPCSTR pszFaceName)
{
    return CreateFontA(cHeight, cWidth, 
        cEscapement, cOrientation, cWeight, bItalic, 
        bUnderline, bStrikeOut, g_systemnnncfg.charset, 
        iOutPrecision, iClipPrecision, 
        iQuality, iPitchAndFamily,  g_systemnnncfg.font);
}

#endif

#if 1 // inline hooks
typedef BOOL (__fastcall *PFN_CPicture_LoadDWQ)(
    void *this, size_t edx, LPSTR fileName, BOOL b256Flag, LPSTR dirName);

BOOL __fastcall CPicture_LoadDWQ_hook(void *this, size_t edx, 
    LPSTR fileName, BOOL b256Flag, LPSTR dirName)
{
    static char tmp[MAX_PATH] = {0};
    printf("CPicture::LoadDWQ %s, %s\n", fileName, dirName);
    PFN_CPicture_LoadDWQ pfn = (PFN_CPicture_LoadDWQ) g_pfnOlds[CPicture_LoadDWQ_IDX];
    BOOL res = pfn(this, edx, fileName, b256Flag, dirName);
    uint8_t *pic = (uint8_t*)*(size_t*)((size_t)this + g_systemnnncfg.CPicture_mpic);
    if (res)
    {
        int x, y, comp;
        char *name = PathFindFileNameA(fileName);
        if (!name) return res;
        sprintf(tmp, "%s\\png\\%s.png", REDIRECT_DIRA, name);
        stbi_uc *img = stbi_load(tmp, &x, &y, &comp, 0);
        if(img)
        {
            printf("-> %s(%dx%d, %d)\n", tmp, x, y, comp);
            for(int i=0;i<x*y;i++) // rgb -> bgr
            {
                pic[4*i] = img[comp*i+2];
                pic[4*i+1] = img[comp*i+1];
                pic[4*i+2] = img[comp*i];
                if(comp==4)   pic[4*i+3] = img[comp*i+3];
            }
            stbi_image_free(img);
        }
    }
    return res;
}
#endif

void install_hooks()
{
    // iat hooks
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
    winhook_patchmemorypattern(g_systemnnncfg.patch);

    // replace dwq dib buffer hook
    g_pfnTargets[CPicture_LoadDWQ_IDX] = (void*)g_systemnnncfg.CPicture_LoadDWQ;
    g_pfnNews[CPicture_LoadDWQ_IDX] = (void*) CPicture_LoadDWQ_hook;
    winhook_inlinehooks(g_pfnTargets, g_pfnNews, g_pfnOlds, 
        sizeof(g_pfnTargets)/sizeof(PVOID));
}

void install_console()
{
    FILE *fp = fopen("systemnnn_patch_console", "rb");
    if(fp)
    {
        AllocConsole();
        freopen("CONOUT$", "w", stdout);
        fclose(fp);
    }
    system("chcp 936");
    setlocale(LC_ALL, "chs");
    printf("systemnnn_patch v0.2.1, build240831, developed by devseed\n");
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
            printf("read systemnnn config %s=%s\n", k, v);
            if(!_stricmp(k, "charset"))
            {
                g_systemnnncfg.charset = atoi(v);
            }
            else if(!_stricmp(k, "font"))
            {
                strcpy(g_systemnnncfg.font, v);
            }
            else if(!_stricmp(k, "patch"))
            {
                strcpy(g_systemnnncfg.patch, v);
            }
            else if(!_stricmp(k, "CPicture_LoadDWQ"))
            {
                g_systemnnncfg.CPicture_LoadDWQ = atoi(v)+ (size_t)GetModuleHandleA(NULL);
            }
            else if(!_stricmp(k, "CPicture_mpic"))
            {
                g_systemnnncfg.CPicture_mpic = atoi(v);
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
            install_console();
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
 * v0.1, initial version, support sjis chcp, range patch, redirect file
 * v0.2, support dwq dib replace
 * v0.2.1, add systemnnn_patch_console file exist detect for allocconsole
*/