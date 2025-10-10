/**
 * majiro engine, localization support
 *   v0.2.3, developed by devseed
 * 
 * note: 
 *   If you want to make compatible for winxp, you can use tcc or llvm-mingw 18 to compile
 *   (mingw-w64 gcc 12 might failed for xp, also you can install One-Core-API)
 * 
 * tested game:
 *   そらいろ (ねこねこソフト) v1.1
 *   (patch=+38C0:C3;+1903B:B8A1;+19087:B8A1;+19A7A:B8A1;+1905D:B9A1;+19AF0:B9A1)
 *    ゆきいろ (ねこねこソフト) v1.2
 *   (patch=+3950:C3;) // patch nodvd
 *   ルリのかさね ～いもうと物語り (ねこねこソフト)
 *   すみれ (ねこねこソフト) v1.02
 *   みずいろ remake (ねこねこソフト) v1.02
 *   (patch=+CE2C4:A1B8;+CE2C8:A1B9)
 * 
 * override/config.ini // number must be decimal except patchpattern, utf16-le
 *   override_file=1
 *   override_codepage=1
 *   codepage=936
 *   override_font=1
 *   createfontcharset=134
 *   enumfontcharset=128
 *   fontname=simhei
 *   usegbk=1
 *   patch=addr:bytes;...
*/

#include <stdio.h>
#include <locale.h>
#include <windows.h>
#include <shlwapi.h>

#define WINOVERRIDE_IMPLEMENTATION
#define WINHOOK_IMPLEMENTATION
#define WINPE_IMPLEMENTATION
#define WINPE_NOASM
#ifdef USECOMPAT
#include "winoverride_v0_1_9.h"
#include "winhook_v0_3_7.h"
#include "winpe_v0_3_8.h"
#else
#include "winoverride.h"
#include "winhook.h"
#include "winpe.h"
#endif

#define CONFIG_PATH "override\\config.ini"

struct majirocfg_t
{
    int usegbk;
};

static struct majirocfg_t g_majirocfg = 
{
    .usegbk=1, 
};

#if 1 // iat hooks
#endif

#if 1 // inline hooks
#endif

#if 1 // patches
static void patch_usegbk()
{
    HMODULE base = GetModuleHandleA(NULL);
    void* addr_cur = (void*)base;
    void* addr_start = (void*)base;
    void* addr_end = (void*)((size_t)base + winpe_imagesizeval((void*)base, 0));
    char patchbytes[3] = {0};
    
    // そらいろ、すみれ
    // 68 75 81 00 00 push 8175h
    addr_cur = addr_start;
    while (addr_cur) 
    {
        addr_cur = winhook_search(addr_cur, (size_t)addr_end - (size_t)addr_cur, "68 75 81 00 00", NULL);
        if (!addr_cur) break;
        winhook_patch(addr_cur, "\x68\xb8\xa1", 3);
        printf("patch at %p [68 b8 a1]\n", addr_cur);
    } 
    // 68 76 81 00 00 push 8176h
    addr_cur = addr_start;
    while (addr_cur) 
    {
        addr_cur = winhook_search(addr_cur, (size_t)addr_end - (size_t)addr_cur, "68 76 81 00 00", NULL);
        if (!addr_cur) break;
        winhook_patch(addr_cur, "\x68\xb9\xa1", 3);
        printf("patch at %p [68 b9 a1]\n", addr_cur);
    } 

    // みずいろ
    //  C7 85 EC F3 FF FF 81 75 00 00  mov dword ptr [ebp+SubStr], 7581h
    addr_cur = addr_start;
    while (addr_cur) 
    {
        addr_cur = winhook_search(addr_cur, (size_t)addr_end - (size_t)addr_cur, "FF FF 81 75 00 00", NULL);
        if(!addr_cur) break;
        winhook_patch(addr_cur, "\xff\xff\xa1\xb8", 4);
        printf("patch at %p [FF FF a1 b8 00 00]\n", addr_cur);
    } 
    //  C7 85 F4 F3 FF FF 81 76 00 00 mov dword ptr [ebp+var_C0C], 7681h
    addr_cur = addr_start;
    while (addr_cur) 
    {
        addr_cur = winhook_search(addr_cur, (size_t)addr_end - (size_t)addr_cur, "FF FF 81 76 00 00", NULL);
        if(!addr_cur) break;
        winhook_patch(addr_cur, "\xff\xff\xa1\xb9", 4);
        printf("patch at %p [FF FF a1 b9 00 00]\n", addr_cur);
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
    addr_cur = winhook_search(addr_cur, (size_t)addr_end - (size_t)addr_cur - sizeof(gbk_table), sjis_pattern, NULL);
    if (addr_cur)
    {
        printf("patch at %p, gbk_table\n", addr_cur);
        winhook_patch(addr_cur, gbk_table, sizeof(gbk_table));
    }
}
#endif

static bool prepare_console(const char *title)
{
    FILE *fp = fopen("DEBUG_CONSOLE", "rb");
    if (!fp) return false;
    fclose(fp);
    AllocConsole();
    freopen("CONOUT$", "w", stdout);
    system("chcp 936");
    setlocale(LC_ALL, "chs");
    SetConsoleTitleA(title);
    puts(title);
    return true;
}

static bool read_config(const char *cfgpath)
{
    struct majirocfg_t *cfg = &g_majirocfg;
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
        LOAD_CFG_INT(usegbk);
    }
#undef LOAD_CFG_INT
#undef LOAD_CFG_STR
    fclose(fp);
    return true;
}

static void init()
{
    read_config(CONFIG_PATH);
    if (g_majirocfg.usegbk) patch_usegbk();
}

static void deinit()
{

}

EXPORT void dummy()
{

}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved)
{
    switch( fdwReason ) 
    { 
        case DLL_PROCESS_ATTACH:
            prepare_console("majiro_patch v0.2.3, developed by devseed");
            winoverride_install(true, CONFIG_PATH);
            init();
            break;
        case DLL_THREAD_ATTACH:
            break;
        case DLL_THREAD_DETACH:
            break;
        case DLL_PROCESS_DETACH:
            deinit();
            winoverride_install(true, CONFIG_PATH);
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
 * v0.2.1, change savedata redirect to relative path
 * v0.2.2, support みずいろ　voice
 * v0.2.3, refract code with winoverride
*/
