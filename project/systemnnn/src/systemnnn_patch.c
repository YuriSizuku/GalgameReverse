/**
 * systemNNN engine 
 * localization support, redirect file, loadpng in dib
 *   v0.2.3, developed by devseed
 * 
 * tested game: 
 *   倭人異聞録～あさき、ゆめみし～ 
 *   (patch=+3DC17:FE;CPicture_LoadDWQ=939744;CPicture_mpic=32)
 * 
 *   EXTRAVAGANZA～蟲愛でる少女～
 *   (patch=+3DC17:FE;CPicture_LoadDWQ=56928;CPicture_mpic=32;CPicture_mpic=40)
 * 
 *   MinDeaD BlooD～麻由と麻奈の輸血箱
 *   (patch=+3DBC7:FE;CPicture_LoadDWQ=939680;CPicture_mpic=32;CPicture_mpic=40)
 *  
 * override/config.ini // number must be decimal except patchpattern,  should be utf-16le
 *   override_file=1
 *   override_font=1
 *   createfontcharset=134
 *   fontname=simhei
 *   patch=xxx
 *   CPicture_LoadDWQ=rva
 *   CPicture_mpic=offset
 *   CPicture_mmaskPic=offset
*/

#include <stdio.h>
#include <locale.h>
#include <windows.h>
#include <shlwapi.h>

#define WINOVERRIDE_IMPLEMENTATION
#define WINOVERRIDE_STATIC
#define WINHOOK_IMPLEMENTATION
#define WINHOOK_STATIC
#define MINHOOK_IMPLEMENTATION
#define MINHOOK_STATIC
#define WINDYN_NOINLINE
#define STB_IMAGE_IMPLEMENTATION
#define STB_IMAGE_STATIC
#define STBI_NO_THREAD_LOCALS
#ifdef __TINYC__
#define STBI_NO_SIMD 
#endif
#ifdef USECOMPAT
#include "winoverride_v0_1_9.h"
#include "winhook_v0_3_7.h"
#include "stb_minhook_v1_3_4.h"
#include "stb_image_v2_2_7_0.h"
#else
#include "winoverride.h"
#include "winhook.h"
#include "stb_minhook.h"
#include "stb_image.h"
#endif

#define CONFIG_PATH "override\\config.ini"

struct systemnnncfg_t
{
    size_t CPicture_LoadDWQ; // addr
    size_t CPicture_mpic; // offset
    size_t CPicture_mmaskPic; // offset
};

static struct systemnnncfg_t g_systemnnncfg = 
{
    .CPicture_LoadDWQ=0, 
    .CPicture_mpic=32, 
    .CPicture_mmaskPic=40
};

#if 1 // iat hooks
#endif

#if 1 // inline hooks
typedef BOOL (__fastcall *T_CPicture_LoadDWQ)(
    void *this, size_t edx, LPSTR fileName, BOOL b256Flag, LPSTR dirName);

MINHOOK_DEFINE(CPicture_LoadDWQ);

static BOOL __fastcall CPicture_LoadDWQ_hook(void *this, size_t edx, 
    LPSTR fileName, BOOL b256Flag, LPSTR dirName)
{
    // https://github.com/tinyan/SystemNNN/blob/afd986747eaab074845cd9217f2427a3a438f5c6/nyanPictureLib/Picture.cpp#L938
    static char tmp[MAX_PATH] = {0};
    LOGi("CPicture::LoadDWQ %s, %s\n", fileName, dirName);
    T_CPicture_LoadDWQ pfn = CPicture_LoadDWQ_org;
    BOOL res = pfn(this, edx, fileName, b256Flag, dirName);
    uint8_t *pic = (uint8_t*)*(size_t*)((size_t)this + g_systemnnncfg.CPicture_mpic);
    uint8_t *mask = (uint8_t*)*(size_t*)((size_t)this + g_systemnnncfg.CPicture_mmaskPic);
    if (res)
    {
        int x, y, comp;
        char *name = PathFindFileNameA(fileName);
        if (!name) return res;
        sprintf(tmp, "png\\%s.png", name);
        stbi_uc *img = stbi_load(tmp, &x, &y, &comp, 0);
        if(img)
        {
            LOGi("-> %s (%dx%d, %d)\n", tmp, x, y, comp);
            for(int i=0;i<x*y;i++) // rgb -> bgr
            {
                pic[4*i] = img[comp*i+2];
                pic[4*i+1] = img[comp*i+1];
                pic[4*i+2] = img[comp*i];
                if(comp==4)
                {
                    pic[4*i+3] = img[comp*i+3];
                    if(mask) mask[i] = img[comp*i+3]; // must should be considered here
                }
            }
            stbi_image_free(img);
        }
    }
    return res;
}
#endif

static bool prepare_console(const char *title)
{
    FILE *fp = fopen("DEBUG_CONSOLE", "rb");
    if (!fp) return false;
    fclose(fp);
    AllocConsole();
    freopen("CONOUT$", "w", stdout);
    SetConsoleCP(936);
    SetConsoleOutputCP(936);
    setlocale(LC_ALL, "chs");
    SetConsoleTitleA(title);
    puts(title);
    return true;
}

static bool read_config(const char *cfgpath)
{
    struct systemnnncfg_t *cfg = &g_systemnnncfg;
    FILE *fp = fopen(cfgpath, "rb");
    if (!fp)
    {
        LOGw("can not find %s\n", cfgpath);
        return false;
    }

    wchar_t line[1024] = {0};
    wchar_t *k = NULL;
    wchar_t *v = NULL;
    fread(line, 2, 1, fp); // skip bom
    if(line[0] != 0xfeff) fseek(fp, 0, SEEK_SET);

#define LOAD_CFG_INT(name) \
    if (!_wcsicmp(k, L"" #name)) cfg->name = _wtoi(v);
#define LOAD_CFG_STR(name) \
    if (!_wcsicmp(k, L"" #name)) wcscpy(cfg->name, v);
    while (fgetws(line, sizeof(line)/2, fp))
    {
        k = wcstok(line, L"=\n\r");
        v = wcstok(NULL, L"=\n\r");
        LOAD_CFG_INT(CPicture_LoadDWQ);
        LOAD_CFG_INT(CPicture_mpic);
        LOAD_CFG_INT(CPicture_mmaskPic);
    }
#undef LOAD_CFG_INT
#undef LOAD_CFG_STR
    fclose(fp);
    return true;
}

static void init()
{
    read_config(CONFIG_PATH);
    size_t base = (size_t)GetModuleHandle(NULL);
    if (g_systemnnncfg.CPicture_LoadDWQ)
    {
        MINHOOK_BINDADDR((void*)(base + g_systemnnncfg.CPicture_LoadDWQ), CPicture_LoadDWQ);
    }
    // if (!PathFileExistsA("./sav"))
    // {
    //     CreateDirectoryA("./sav",NULL);
    // }
}

static void deinit()
{
    if (g_systemnnncfg.CPicture_LoadDWQ)
    {
        MINHOOK_UNBIND(CPicture_LoadDWQ);
    }
}

EXPORT void dummy()
{

}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved)
{
    switch( fdwReason ) 
    { 
        case DLL_PROCESS_ATTACH:
            prepare_console("systemnnn_patch v0.2.3, developed by devseed");
            winoverride_install(true, CONFIG_PATH);
            init();
            break;
        case DLL_THREAD_ATTACH:
            break;
        case DLL_THREAD_DETACH:
            break;
        case DLL_PROCESS_DETACH:
            deinit();
            winoverride_uninstall(true);
            break;
    }
    return TRUE;
}

/** history
 * v0.1, initial version, support sjis chcp, range patch, redirect file
 * v0.2, support dwq dib replace
 * v0.2.1, add systemnnn_patch_console file exist detect for allocconsole
 * v0.2.2, add m_maskPic for dwq blending problem
 * v0.2.3, refactor with winoverride
*/