/**
 *  dynamicly compute dirhash and filehash in list
 *   v0.1, developed by devseed
 * 
 * build:
 *   clang++ -m32 -shared -Wno-null-dereference -Isrc/compat -DUSECOMPAT src/krkr_hxv4_dumphash.cpp src/compat/tp_stub.cpp src/compat/winversion_v100.def -o asset/build/version.dll -g -gcodeview -Wl,--pdb=asset/build/version.pdb 
 * 
 * usage:
 *    compile and then put version.dll into game directory, 
 *    then it will decodes all the lines as name in files.txt and dirs.txt
 *    files.txt -> files_match.txt, dirs.txt -> dirs_match.txt (must be utf16lebom)
 *    after that you can restore content path extracted by KrkrExtractForCxdecV2
 * 
 * tested games:
 *   D.C.5 Plus Happiness ～ダ・カーポ5～プラスハピネス
 * 
 * refer: 
 *   https://github.com/YeLikesss/KrkrExtractForCxdecV2/blob/main/CxdecStringDumper/HashCore.cpp
 */

#include <cstdio>
#include <cstdint>
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

// hxv4 functions and struct
typedef struct Hxv4CompoundHasher Hxv4CompoundHasher;
typedef  tjs_int(__fastcall *FuncHxv4CalcHash)(Hxv4CompoundHasher* _this, void* _edx, 
    OUT tTJSVariant* hash, const tTJSString* str, const tTJSString* seed);

typedef struct Hxv4CompoundHasher
{
    struct 
    {
        void* destruct;
        FuncHxv4CalcHash calc;
    } *vftable; // offset 0
    tjs_uint8* salt;  // offset 0x4
    tjs_int saltsize; // offset 0x8
} Hxv4CompoundHasher;

typedef struct Hxv4DirHasher
{
    Hxv4CompoundHasher base;
    tjs_uint8 saltdata[0x10];
} Hxv4DirHasher;

typedef struct Hxv4FileHasher
{
    Hxv4CompoundHasher base;
    tjs_uint8 saltdata[0x20];
} Hxv4FileHasher;

typedef struct Hxv4CompoundStorageMedia
{
    void* vftable;
    int nref;
    uint32_t reserve1;
    tTJSString prefix; 
    tTJSString seed; //offset 0x10
    CRITICAL_SECTION critical_section;
    uint8_t reserve2[0x20];
    tTJSString* start;
    tTJSString* pos;
    tTJSString* end;
    Hxv4DirHasher* dirhasher; // offset 0x58
    Hxv4FileHasher* filehasher;
} Hxv4CompoundStorageMedia;

//  func type declear
DWORD WINAPI calc_thread(void *arg);
HRESULT __stdcall V2Link_hook(iTVPFunctionExporter* exporter);
tjs_error _cdecl CreateHxv4CompoundStorageMedia_hook(Hxv4CompoundStorageMedia **ret, 
    tTJSVariant *prefix, int argc, char *argv[]);

// global value define
#define FILELISTNAME "files"
#define DIRLISTNAME "dirs"
HANDLE LoadlibraryW_mutex = nullptr;
decltype(LoadLibraryW) *LoadlibraryW_org = nullptr;
decltype(V2Link_hook) *V2Link_org = nullptr;
void *V2Link_old = nullptr;
decltype(CreateHxv4CompoundStorageMedia_hook) *CreateHxv4CompoundStorageMedia_org = nullptr;
void *CreateHxv4CompoundStorageMedia_old = nullptr;
const char *CreateHxv4CompoundStorageMedia_sig = (const char *)"55 8b ec 6a ff 68 ? ? ? ? 64 a1 00 00 00 00 50 83 ec 08 56 a1 ? ? ? ? 33 c5 50 8d 45 f4 64 a3 00 00 00 00 a1 ? ? ? ? 85 c0 75 12 68 ? ? ? ? e8 ? ? ? ? 83 c4 04 a3 ? ? ? ? 8b 75 0c 56 ff d0 83 f8 02 74 ? b8 15 fc ff ff 8b 4d f4 64 89 0d 00 00 00 00 59 5e 8b e5 5d c3";

HRESULT __stdcall V2Link_hook(iTVPFunctionExporter* exporter)
{
    LOGi("exporter %p\n", exporter);
    TVPInitImportStub(exporter); // must bind exporter here
    MH_DisableHook(V2Link_old);
    return V2Link_org(exporter);
}

// hook functions
tjs_error _cdecl CreateHxv4CompoundStorageMedia_hook(Hxv4CompoundStorageMedia **ret, tTJSVariant *prefix, int argc, char *argv[])
{
    auto err = CreateHxv4CompoundStorageMedia_org(ret, prefix, argc, argv);
    LOGi("Hxv4CompoundStorageMedia at %p\n", *ret);
    MH_DisableHook(CreateHxv4CompoundStorageMedia_old);;
    CreateThread(NULL, 0, calc_thread, (LPVOID)*ret, 0, NULL);
    return err;
}

HMODULE LoadLibraryW_hook(LPCWSTR name)
{
    WaitForSingleObject(LoadlibraryW_mutex, INFINITE);
    auto hmod = LoadlibraryW_org(name);
    // LOGLi(L"LoadLibraryW name=%ls hmod=%p\n", name, hmod);
    if(wcsstr(name, L"krkr_"))
    {
        size_t dllsize = winhook_getimagesize(GetCurrentProcess(), hmod);
        LOGi("load cxdec.tpm dllbase=%p dllsize=0x%zx\n", hmod, dllsize);
        
        // hook V2Link
        auto addr = reinterpret_cast<void*>(GetProcAddress(hmod, "V2Link"));
        if(addr)
        {
            MH_CreateHook(addr,  reinterpret_cast<LPVOID>(V2Link_hook),  
                reinterpret_cast<LPVOID*>(&V2Link_org));
            LOGi("MH_CreateHook V2Link %p -> %p\n", addr, V2Link_hook);
            MH_EnableHook(addr);
            V2Link_old = addr;
        }

        // hook CreateHxv4CompoundStorageMedia
        addr = winhook_searchmemory((void*)hmod, dllsize, CreateHxv4CompoundStorageMedia_sig, NULL);
        LOGi("search CreateHxv4CompoundStorageMedia va=%p rva=0x%zx\n", addr, (size_t)addr - (size_t)hmod);
        if(addr)
        {
            MH_CreateHook(addr,  reinterpret_cast<LPVOID>(CreateHxv4CompoundStorageMedia_hook),  
                reinterpret_cast<LPVOID*>(&CreateHxv4CompoundStorageMedia_org));
            LOGi("MH_CreateHook CreateHxv4CompoundStorageMedia %p -> %p\n", addr, CreateHxv4CompoundStorageMedia_hook);
            MH_EnableHook(addr);
            CreateHxv4CompoundStorageMedia_old = addr;
        }
        MH_DisableHook(reinterpret_cast<LPVOID>(LoadLibraryW)); // must disable or has problem on dx2d
    }
    ReleaseMutex(LoadlibraryW_mutex);
    return hmod;
}

const wchar_t* WINAPI calc_name_hexify(Hxv4CompoundHasher *hasher, tTJSString *seed, const wchar_t* name)
{
    static wchar_t hashstrw[0x64] = {0};
    tTJSVariant hashvar;
    tTJSString targetstr(name);
    tjs_int hashsize = hasher->vftable->calc(hasher, nullptr, &hashvar, &targetstr, seed);
    tTJSVariantOctet* hashoctet = hashvar.AsOctetNoAddRef();
    const uint8_t* data = hashoctet->GetData();
    inl_hexifyw(hashstrw, sizeof(hashstrw)/2, data, hashsize, nullptr);
    return hashstrw;
}

DWORD WINAPI calc_list(Hxv4CompoundHasher *hasher, tTJSString *seed, const char *inpath, const char *outpath)
{
    int i = 0;
    uint16_t bom;
    static wchar_t linestrw[0x200];
    FILE *fp1 = fopen(inpath, "rb");
    FILE *fp2 = fopen(outpath, "wb");
    fwrite("\xff\xfe", 1, 2, fp2);
    fread(&bom, 2, 1, fp1);
    if(bom != 0xfeff) fseek(fp1, 0, SEEK_SET);
    while(fgetws(linestrw, sizeof(linestrw)/2, fp1))
    {
        i++;
        if (linestrw[wcslen(linestrw)-2] == L'\r') linestrw[wcslen(linestrw)-2] = 0;
        if (linestrw[wcslen(linestrw)-1] == L'\n') linestrw[wcslen(linestrw)-1] = 0;
        const wchar_t *hashstrw = calc_name_hexify(hasher, seed, linestrw);
        LOGLi(L"%ls,%ls\n", linestrw, hashstrw);
        fwrite(linestrw, 2, wcslen(linestrw), fp2); // fwprintf has problem
        fwrite(L",", 2, 1, fp2);
        fwrite(hashstrw, 2, wcslen(hashstrw), fp2);
        fwrite(L"\r\n", 2, 2, fp2);
        fflush(fp2);
    }
    fclose(fp1);
    fclose(fp2);
    return i;
}

DWORD WINAPI calc_thread(void *arg)
{
    // Sleep(400); // simply wait for V2Link finish
    auto media = reinterpret_cast<Hxv4CompoundStorageMedia*>(arg);
    auto filehasher = media->filehasher;
    auto dirhasher = media->dirhasher;
    
    FILE *fp1;
    FILE *fp2;
    uint16_t bom;
    wchar_t tmp[0x100];
    wchar_t linestrw[0x200];
    wchar_t hashstrw[0x64] = {0};
    LOGLi(L"seed=%ls\n", media->seed.c_str());
    
    LOGi("try to calc names in %s\n", FILELISTNAME".txt");
    calc_list(&filehasher->base, &media->seed, FILELISTNAME".txt", FILELISTNAME"_match.txt");
    LOGi("try to calc names in %s\n", DIRLISTNAME".txt");
    calc_list(&dirhasher->base, &media->seed, DIRLISTNAME".txt", DIRLISTNAME"_match.txt");
    LOGi("calculate finish, results in %s, %s\n", FILELISTNAME"_match.txt", DIRLISTNAME"_match.txt");

    return 0;
}

static void init()
{
    AllocConsole();
    freopen("CONOUT$", "w", stdout);
    // system("chcp 936");
    // setlocale(LC_ALL, "chs");
    printf("krkr_hxv4_hash calculator, v0.1, developed by devseed\n");
    
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

    auto status = MH_Initialize();
    if(status != MH_OK)
    {
        LOGe("MH_Initialize failed\n");
        return;
    }

    LoadlibraryW_mutex = CreateMutexA(NULL, FALSE, NULL);
    status = MH_CreateHook(reinterpret_cast<LPVOID*>(LoadLibraryW), 
        reinterpret_cast<LPVOID*>(LoadLibraryW_hook), 
        reinterpret_cast<LPVOID*>(&LoadlibraryW_org));
    LOGi("MH_CreateHook LoadLibraryW %p -> %p\n", LoadLibraryW, LoadLibraryW_hook);
    status = MH_EnableHook(reinterpret_cast<LPVOID>(LoadLibraryW));
    if(status != MH_OK)
    {
        LOGe("MH_EnableHook LoadLibraryW failed");
        return;
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
            break;
    }
    return TRUE;
}