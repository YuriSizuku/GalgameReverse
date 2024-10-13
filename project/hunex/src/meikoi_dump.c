/**
 * An experiment for invoking il2cpp function
 * to dump xxx.hpb(hph) in 明治東亰恋伽 
 *   v0.1, developed by devseed
 * 
 *  build:
 *    // install llvm-mingw to build
 *    // https://github.com/mstorsjo/llvm-mingw/releases/download/20240619/llvm-mingw-20240619-msvcrt-x86_64.zip
 *    clang src/meikoi_dump.c -o asset/build/meikoi_dump.dll -shared -g -gcodeview -Wl,--pdb=asset/build/majiro_dump.pdb
 * 
 *  usage: 
 *    // copy meikoi_dump.dll, winloader64.exe into game dir
 *    // https://github.com/YuriSizuku/ReverseTool/releases/download/v0.3.7.1/winloader64.exe
 *    winloader64 meikoi.exe meikoi_dump.dll
 *
 */

#include <stdio.h>
#include <stdint.h>
#include <assert.h>
#include <direct.h>
#include <sys/stat.h>
#include <windows.h>

// il2cpp sturcture and function
typedef uintptr_t il2cpp_array_size_t;
typedef int32_t il2cpp_array_lower_bound_t;
typedef struct Il2CppClass Il2CppClass;
typedef struct MethodInfo MethodInfo;
typedef struct Il2CppDomain Il2CppDomain;
typedef struct Il2CppThread Il2CppThread;

typedef struct Il2CppObject
{
    Il2CppClass *klass;
    void *monitor;
}Il2CppObject;

typedef struct Il2CppArrayBounds
{
    il2cpp_array_size_t length;
    il2cpp_array_lower_bound_t lower_bound;
}Il2CppArrayBounds;

typedef struct System_Byte_array {
	Il2CppObject obj;
	Il2CppArrayBounds *bounds;
	il2cpp_array_size_t max_length;
	uint8_t m_Items[65535];
}System_Byte_array;

typedef Il2CppDomain* (*PFN_il2cpp_domain_get)();

typedef Il2CppThread* (*PFN_il2cpp_thread_attach)(Il2CppDomain *domain);

typedef void* (*PFN_il2cpp_array_new_specific) (
    Il2CppClass *arrayTypeInfo, 
    il2cpp_array_size_t length);

typedef int (__stdcall *PFN_UnityMain)(
    HINSTANCE hInstance, 
    HINSTANCE hPrevInstance, 
    LPSTR lpCmdLine, 
    int nShowCmd);

// meikoi struct and function
typedef struct HLZS_Head {
	uint32_t id;
	uint32_t version;
	uint32_t encodeSize;
	uint32_t decodeSize;
} HLZS_Head;

typedef struct HPAC_Head {
	uint32_t id;
	uint32_t version;
	int32_t count;
	uint32_t size;
	uint32_t nameOffset;
    void *padding;
} HPAC_Head;

typedef struct HPAC_Entry {
	int64_t offset;
	uint32_t key;
	uint32_t fileSize;
	uint32_t meltSize;
	uint32_t fileCRC;
	uint32_t meltCRC;
} HPAC_Entry;

typedef int (*PFN_hunex_UNAS_Systems_Compress_unas_LZSDecode__Decode)(
    System_Byte_array *inData,
    int32_t offset,
    System_Byte_array **outData,
    const MethodInfo *method);

// hard coded structure or function rva
Il2CppClass *byte___TypeInfo = (Il2CppClass*)0x2BBC778;
PFN_il2cpp_array_new_specific il2cpp_array_new_specific = (PFN_il2cpp_array_new_specific)0x3A3FF0;
PFN_il2cpp_domain_get il2cpp_domain_get = (PFN_il2cpp_domain_get)0x3A49E0;
PFN_il2cpp_thread_attach il2cpp_thread_attach = (PFN_il2cpp_thread_attach)0x3A5AF0;
PFN_hunex_UNAS_Systems_Compress_unas_LZSDecode__Decode 
    hunex_UNAS_Systems_Compress_unas_LZSDecode__Decode = 
    (PFN_hunex_UNAS_Systems_Compress_unas_LZSDecode__Decode)0x65C710;

// hard coded config 
#define OUT_DIR "dump"
const char *hpb_list[] ={
    "meikoi_Data/StreamingAssets/data.hpb", 
    "meikoi_Data/StreamingAssets/adv.hpb", 
    "meikoi_Data/StreamingAssets/bgm.hpb", 
    "meikoi_Data/StreamingAssets/voice.hpb", 
    NULL
};

void init_console()
{
    AllocConsole();
    freopen("CONOUT$", "w", stdout);    
    freopen("CONOUT$", "w", stderr);    
}

void init_il2()
{
    HMODULE hmod = LoadLibraryA("GameAssembly.dll");
    if(!hmod) fprintf(stderr, "can not load GameAssembly.dll\n");
    printf("[init_il2] load GameAssembly.dll hmod=%p\n", hmod);
    byte___TypeInfo = (Il2CppClass*)((size_t)byte___TypeInfo + (size_t)hmod);
    hunex_UNAS_Systems_Compress_unas_LZSDecode__Decode = (PFN_hunex_UNAS_Systems_Compress_unas_LZSDecode__Decode)
        ((size_t)hunex_UNAS_Systems_Compress_unas_LZSDecode__Decode+ (size_t)hmod);
    il2cpp_array_new_specific = (PFN_il2cpp_array_new_specific)((size_t)il2cpp_array_new_specific+ (size_t)hmod);
    il2cpp_domain_get = (PFN_il2cpp_domain_get)((size_t)il2cpp_domain_get+ (size_t)hmod);
    il2cpp_thread_attach = (PFN_il2cpp_thread_attach)((size_t)il2cpp_thread_attach+ (size_t)hmod);
}

void decode_hlzs(const char *inpath, size_t offset, size_t size, const char *outpath)
{
    FILE *fp = fopen(inpath, "rb");
    if(!fp)
    {
        fprintf(stderr, "[decode_hlzs] inpath %s not found!", inpath);
        return;
    }
    if(!size)
    {
        struct stat st;
        stat(inpath, &st);
        size = st.st_size;
    }

    // this will not works if il2cpp vm not start
    // System_Byte_array *indata = (System_Byte_array*)il2cpp_array_new_specific(byte___TypeInfo, size);
    System_Byte_array *indata = (System_Byte_array*)malloc(size + sizeof(System_Byte_array) - 65535);
    indata->obj.klass = byte___TypeInfo;
    indata->max_length = size;
    memset(indata->m_Items, 0, indata->max_length); 
    fseek(fp, offset, SEEK_SET); // skip zero in file head
    fread((void*)indata->m_Items, 1, size, fp);
    fclose(fp);

    HLZS_Head *lzs_head = (HLZS_Head*)indata->m_Items;
    if(strncmp((const char *)&lzs_head->id, "HLZS", 4))
    {
        free(indata);
        return;
    }
    printf("[decode_hlzs] inpath=%s outpath=%s encodeSize=0x%x decodeSize=0x%x\n", 
                inpath, outpath, lzs_head->encodeSize, lzs_head->decodeSize);
    System_Byte_array *outdata = (System_Byte_array*)il2cpp_array_new_specific(byte___TypeInfo, 0);
    hunex_UNAS_Systems_Compress_unas_LZSDecode__Decode(indata, 0, &outdata, NULL);
    assert(outdata->max_length == lzs_head->decodeSize); // need to deref System_Byte_array ? 
    free(indata);

    fp = fopen(outpath, "wb");
    if(!fp)
    {
        fprintf(stderr, "outpath %s creat error!", outpath);
        return;
    }
    fwrite(outdata->m_Items, 1, outdata->max_length, fp);
    fclose(fp);
}

void extract_hpb(const char *hpbpath, const char *outdir)
{
    char *p = NULL;
    char hphpath[MAX_PATH];
    char inname[16];
    char outpath[MAX_PATH];
    strcpy(hphpath, hpbpath);
    p = strrchr(hphpath, '.');
    strcpy(p, ".hph");
    p = strrchr(hphpath, '/') + 1;
    strcpy(inname, p);
    p = strrchr(inname, '.');
    *p = '\0';
    FILE *fp = fopen(hphpath, "rb");
    if(!fp)
    {
        fprintf(stderr, "[extract_hpb] %s not found!", hphpath);
        return;
    }
    
    HPAC_Head hpc_head = {0};
    HPAC_Entry hpc_entry = {0};
    fread(&hpc_head, sizeof(HPAC_Head), 1, fp);
    if(strncmp((const char *)&hpc_head.id, "HPAC", 4))
    {
        fprintf(stderr, "[extract_hpb] %s not valid hph file!", hphpath);
        fclose(fp);
        return;
    }
    printf("[extract_hpb] hphpath=%s version=%x count=%d size=%x\n", 
            hphpath, hpc_head.version, hpc_head.count, hpc_head.size);
    for(int i=0; i < hpc_head.count; i++)
    {
        fread(&hpc_entry, sizeof(HPAC_Entry), 1, fp);
        if(hpc_entry.fileSize==0) continue;
        printf("[extract_hpb] entry_no=%d offset=0x%08llx fileSize=0x%08x meltSize=0x%08x fileCrc=0x%08x meltCrc=0x%08x\n",
                    i, hpc_entry.offset, hpc_entry.fileSize, hpc_entry.meltSize, 
                    hpc_entry.fileCRC, hpc_entry.meltCRC);
        sprintf(outpath, "%s/%s_%08llx.dec", outdir, inname, hpc_entry.offset);
        decode_hlzs(hpbpath, hpc_entry.offset, hpc_entry.fileSize, outpath);
    }
    printf("[extract_hpb] %s extract finish! \n", hphpath);
    fclose(fp);
}

DWORD WINAPI thread_dump(void* data) 
{
    Sleep(10000); // wait for il2cpp vm start
    il2cpp_thread_attach(il2cpp_domain_get()); // must attach to thread to invoke il2 function
    mkdir(OUT_DIR);
    for(int i=0; hpb_list[i]; i++)
    {
        extract_hpb(hpb_list[i], OUT_DIR);
    }
    return 0;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved )  // reserved
{
    switch( fdwReason ) 
    { 
        case DLL_PROCESS_ATTACH:
            // MessageBox(NULL, "meikoi_hpb.dll start", "mekoi_hpb", 0);
            init_console();
            init_il2();
            CreateThread(NULL, 0, thread_dump, NULL, 0, NULL);
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