/*
This tool is for parsing windows pe structure, adjust realoc addrs, or iat.
Most functions are independent by INLINE all parts, 
so that this can also be used as shellcode
    v0.3.5, developed by devseed 
*/

#ifndef _WINPE_H
#define _WINPE_H
#define WINPE_VERSION 350

#include <stdint.h>
#include <windows.h>
#include <winternl.h>

#ifndef WINPEDEF
#ifdef WINPE_STATIC
#define WINPEDEF static
#else
#define WINPEDEF extern
#endif
#endif

#ifndef WINPE_SHARED
#define WINPE_EXPORT
#else
#if defined(_WIN32)
#define WINPE_EXPORT __declspec(dllexport)
#else
#define WINPE_EXPORT __attribute__((visibility("default")))
#endif
#endif

#if defined(_WIN32)
#ifndef STDCALL
#define STDCALL __stdcall
#endif
#ifdef NAKED
#define NAKED __declspec(naked)
#endif
#else
#ifndef STDCALL
#define STDCALL __attribute__((stdcall))
#endif
#ifdef NAKED
#define NAKED __attribute__((naked))
#endif
#endif

#ifndef INLINE
#if defined(_MSC_VER) 
#define INLINE __forceinline
#else  // tcc, gcc not support inline export, tcc inline will output nofunction ...
#define INLINE
#endif
#endif

#ifdef __cplusplus
extern "C" {
#endif
typedef struct _RELOCOFFSET
{
    WORD offset : 12;
    WORD type   : 4;
}RELOCOFFSET,*PRELOCOFFSET;

typedef int bool_t;

typedef HMODULE (WINAPI *PFN_LoadLibraryA)(
    LPCSTR lpLibFileName);

typedef FARPROC (WINAPI *PFN_GetProcAddress)(
    HMODULE hModule, LPCSTR lpProcName);

typedef PFN_GetProcAddress PFN_GetProcRVA;

typedef LPVOID (WINAPI *PFN_VirtualAlloc)(
    LPVOID lpAddress, SIZE_T dwSize, 
    DWORD  flAllocationType, DWORD flProtect);

typedef BOOL (WINAPI *PFN_VirtualFree)(
    LPVOID lpAddress, SIZE_T dwSize, 
    DWORD dwFreeType);

typedef BOOL (WINAPI *PFN_VirtualProtect)(
    LPVOID lpAddress, SIZE_T dwSize,
    DWORD  flNewProtect, PDWORD lpflOldProtect);

typedef SIZE_T (WINAPI *PFN_VirtualQuery)(
    LPCVOID lpAddress,
    PMEMORY_BASIC_INFORMATION lpBuffer,
    SIZE_T dwLength);

typedef BOOL (WINAPI *PFN_DllMain)(HINSTANCE hinstDLL,
    DWORD fdwReason, LPVOID lpReserved );

#define WINPE_LDFLAG_MEMALLOC 0x1
#define WINPE_LDFLAG_MEMFIND 0x2

// PE high order fnctions
/*
  load the origin rawpe file in memory buffer by mem align
  mempe means the pe in memory alignment
    return mempe buffer, memsize
*/
WINPEDEF WINPE_EXPORT 
void* STDCALL winpe_memload_file(const char *path, 
    size_t *pmemsize, bool_t same_align);

/*
  load the overlay data in a pe file
    return overlay buf, overlay size
*/
WINPEDEF WINPE_EXPORT
void* STDCALL winpe_overlayload_file(const char *path, 
    size_t *poverlaysize);

/*
  similar to LoadlibrayA, will call dllentry
  will load the mempe in a valid imagebase
    return hmodule base
*/
WINPEDEF WINPE_EXPORT
INLINE void* STDCALL winpe_memLoadLibrary(void *mempe);

/*
  if imagebase==0, will load on mempe, or in imagebase
  will load the mempe in a valid imagebase, flag as below:
    WINPE_LDFLAG_MEMALLOC 0x1, will alloc memory to imagebase
    WINPE_LDFLAG_MEMFIND 0x2, will find a valid space, 
        must combined with WINPE_LDFLAG_MEMALLOC
    return hmodule base
*/
WINPEDEF WINPE_EXPORT 
INLINE void* STDCALL winpe_memLoadLibraryEx(void *mempe, 
    size_t imagebase, DWORD flag,
    PFN_LoadLibraryA pfnLoadLibraryA, 
    PFN_GetProcAddress pfnGetProcAddress);

/*
   similar to FreeLibrary, will call dllentry
     return true or false
*/
WINPEDEF WINPE_EXPORT
INLINE BOOL STDCALL winpe_memFreeLibrary(void *mempe);

/*
   FreeLibraryEx with VirtualFree custom function
     return true or false
*/
WINPEDEF WINPE_EXPORT
INLINE BOOL STDCALL winpe_memFreeLibraryEx(void *mempe, 
    PFN_LoadLibraryA pfnLoadLibraryA, 
    PFN_GetProcAddress pfnGetProcAddress);


/*
   similar to GetProcAddress
     return function va
*/
WINPEDEF WINPE_EXPORT
INLINE PROC STDCALL winpe_memGetProcAddress(
    void *mempe, const char *funcname);

// PE query functions
/*
   use peb and ldr list, to obtain to find kernel32.dll address
     return kernel32.dll address
*/
WINPEDEF WINPE_EXPORT
INLINE void* winpe_findkernel32();

/*
   use peb and ldr list, similar as GetModuleHandleA
     return ldr module address
*/
WINPEDEF WINPE_EXPORT
INLINE void* STDCALL winpe_findmoduleaex(
    PPEB peb, char *modulename);
#define winpe_findmodulea(modulename) winpe_findmoduleaex(NULL, modulename)

/*
     return LoadLibraryA func addr
*/
WINPEDEF WINPE_EXPORT
INLINE PROC winpe_findloadlibrarya();

/*
     return GetProcAddress func addr
*/
WINPEDEF WINPE_EXPORT
INLINE PROC winpe_findgetprocaddress();

/*
    find a valid space address start from imagebase with imagesize
    use PFN_VirtualQuery for better use 
      return va with imagesize
*/
WINPEDEF WINPE_EXPORT
INLINE void* STDCALL winpe_findspace(
    size_t imagebase, size_t imagesize, size_t alignsize,
    PFN_VirtualQuery pfnVirtualQuery);

// PE load, adjust functions
/*
  for overlay section in a pe file
    return the overlay offset
*/
WINPEDEF WINPE_EXPORT 
INLINE size_t STDCALL winpe_overlayoffset(const void *rawpe);

/*
  load the origin rawpe in memory buffer by mem align
    return memsize
*/
WINPEDEF WINPE_EXPORT 
INLINE size_t STDCALL winpe_memload(
    const void *rawpe, size_t rawsize, 
    void *mempe, size_t memsize, 
    bool_t same_align);

/*
  realoc the addrs for the mempe addr as image base
  origin image base usually at 0x00400000, 0x0000000180000000
  new image base mush be divided by 0x10000, if use loadlibrary
    return realoc count
*/
WINPEDEF WINPE_EXPORT 
INLINE size_t STDCALL winpe_memreloc(
    void *mempe, size_t newimagebase);

/*
  load the iat for the mempe, use rvafunc for winpe_memfindexp 
    return iat count
*/
WINPEDEF WINPE_EXPORT 
INLINE size_t STDCALL winpe_membindiat(void *mempe, 
    PFN_LoadLibraryA pfnLoadLibraryA, 
    PFN_GetProcAddress pfnGetProcAddress);

/*
  exec the tls callbacks for the mempe, before dll oep load
  reason is for function PIMAGE_TLS_CALLBACK
    return tls count
*/
WINPEDEF WINPE_EXPORT 
INLINE size_t STDCALL winpe_membindtls(void *mempe, DWORD reason);

/*
  find the iat addres, for call [iat]
    return target iat va
*/
WINPEDEF WINPE_EXPORT
INLINE void* STDCALL winpe_memfindiat(void *mempe, 
    LPCSTR dllname, LPCSTR funcname);

/*
  find the exp  addres, the same as GetProcAddress
  without forward to other dll
  such as NTDLL.RtlInitializeSListHead
    return target exp va
*/
WINPEDEF WINPE_EXPORT 
INLINE void* STDCALL winpe_memfindexp(
    void *mempe, LPCSTR funcname);


WINPEDEF WINPE_EXPORT
INLINE void* STDCALL winpe_memfindexpcrc32(
    void* mempe, uint32_t crc32);

/*
  forward the exp to the final expva
    return the final exp va
*/
WINPEDEF WINPE_EXPORT
INLINE void* STDCALL winpe_memforwardexp(
    void *mempe, size_t exprva, 
    PFN_LoadLibraryA pfnLoadLibraryA, 
    PFN_GetProcAddress pfnGetProcAddress);

// PE modify function
/* 
  change the oep of the pe if newoeprva!=0
    return the old oep rva
*/
WINPEDEF WINPE_EXPORT
INLINE DWORD STDCALL winpe_oepval(
    void *mempe, DWORD newoeprva);

/* 
  change the imagebase of the pe if newimagebase!=0
    return the old imagebase va
*/
WINPEDEF WINPE_EXPORT
INLINE size_t STDCALL winpe_imagebaseval(
    void *mempe, size_t newimagebase);

/* 
  change the imagesize of the pe if newimagesize!=0
    return the old imagesize
*/
WINPEDEF WINPE_EXPORT
INLINE size_t STDCALL winpe_imagesizeval(
    void *pe, size_t newimagesize);

/*
    close the aslr feature of an pe
*/
WINPEDEF WINPE_EXPORT
INLINE void STDCALL winpe_noaslr(void *pe);

/* 
  Append a section header in a pe, sect rva will be ignored
  the mempe size must be enough for extend a section
    return image size
*/
WINPEDEF WINPE_EXPORT 
INLINE size_t STDCALL winpe_appendsecth(
    void *mempe, PIMAGE_SECTION_HEADER psecth);


#ifdef __cplusplus
}
#endif


#ifdef WINPE_IMPLEMENTATION

#ifndef _DEBUG
#ifndef NDEBUG
#define NDEBUG
#endif
#endif

#if defined(__TINYC__)
#ifdef _WIN64
#pragma pack(8)
#else
#pragma pack(4)
#endif
#endif

#include <stdio.h>
#include <assert.h>
#include <windows.h>
#include <winternl.h>

// util INLINE functions
INLINE size_t _winpeinl_strlen(const char* str1)
{
    const char* p = str1;
    while(*p) p++;
    return p - str1;
}

INLINE int _winpeinl_stricmp(const char *str1, const char *str2)
{
    int i=0;
    while(str1[i]!=0 && str2[i]!=0)
    {
        if (str1[i] == str2[i] 
        || str1[i] + 0x20 == str2[i] 
        || str2[i] + 0x20 == str1[i])
        {
            i++;
        }
        else
        {
            return (int)str1[i] - (int)str2[i];
        }
    }
    return (int)str1[i] - (int)str2[i];
}

INLINE int _winpeinl_stricmp2(const char *str1, const wchar_t* str2)
{
    int i=0;
    while(str1[i]!=0 && str2[i]!=0)
    {
        if ((wchar_t)str1[i] == str2[i] 
        || (wchar_t)str1[i] + 0x20 == str2[i] 
        || str2[i] + 0x20 == (wchar_t)str1[i])
        {
            i++;
        }
        else
        {
            return (int)str1[i] - (int)str2[i];
        }
    }
    return (int)str1[i] - (int)str2[i];
}

INLINE uint32_t _winpeinl_crc32(const void *buf, size_t n)
{
    uint32_t crc32 = ~0;
    for(size_t i=0; i< n; i++)
    {
        crc32 ^= *(const uint8_t*)((uint8_t*)buf+i);

        for(int i = 0; i < 8; i++)
        {
            uint32_t t = ~((crc32&1) - 1); 
            crc32 = (crc32>>1) ^ (0xEDB88320 & t);
        }
    }
    return ~crc32;
}

INLINE void* _winpeinl_memset(void *buf, int ch, size_t n)
{
    char *p = buf;
    for(size_t i=0;i<n;i++) p[i] = (char)ch;
    return buf;
}

INLINE void* _winpeinl_memcpy(void *dst, const void *src, size_t n)
{
    char *p1 = (char*)dst;
    char *p2 = (char*)src;
    for(size_t i=0;i<n;i++) p1[i] = p2[i];
    return dst;
}

// PE high order fnctions
WINPEDEF WINPE_EXPORT 
void* STDCALL winpe_memload_file(const char *path, 
    size_t *pmemsize, bool_t same_align)
{
    FILE *fp = fopen(path, "rb");
    fseek(fp, 0, SEEK_END);
    size_t rawsize = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    void *rawpe = malloc(rawsize);
    fread(rawpe, 1, rawsize, fp);
    fclose(fp);

    void *mempe = NULL;
    if(pmemsize)
    {
        *pmemsize = winpe_memload(rawpe, 0, NULL, 0, FALSE);
        mempe = malloc(*pmemsize);
        winpe_memload(rawpe, rawsize, mempe, *pmemsize, same_align);
    }
    free(rawpe);
    return mempe;
}

WINPEDEF WINPE_EXPORT 
void* STDCALL winpe_overlayload_file(
    const char *path, size_t *poverlaysize)
{
    FILE *fp = fopen(path, "rb");
    fseek(fp, 0, SEEK_END);
    size_t rawsize = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    void *rawpe = malloc(rawsize);
    fread(rawpe, 1, rawsize, fp);
    fclose(fp);
    void *overlay = NULL;
    size_t overlayoffset = winpe_overlayoffset(rawpe);
    
    if(poverlaysize)
    {
        *poverlaysize = rawsize - overlayoffset;
        if(*poverlaysize>0)
        {
            overlay = malloc(*poverlaysize);
            memcpy(overlay, (uint8_t*)rawpe+overlayoffset, *poverlaysize);
        }
    }
    free(rawpe);
    return overlay;
}

WINPEDEF WINPE_EXPORT  
INLINE void* STDCALL winpe_memLoadLibrary(void *mempe)
{
    PFN_LoadLibraryA pfnLoadLibraryA = 
        (PFN_LoadLibraryA)winpe_findloadlibrarya();
    PFN_GetProcAddress pfnGetProcAddress = 
        (PFN_GetProcAddress)winpe_findgetprocaddress();
    return winpe_memLoadLibraryEx(mempe, 0, 
        WINPE_LDFLAG_MEMFIND | WINPE_LDFLAG_MEMALLOC, 
        pfnLoadLibraryA, pfnGetProcAddress);
}

WINPEDEF WINPE_EXPORT
INLINE void* STDCALL winpe_memLoadLibraryEx(void *mempe, 
    size_t imagebase, DWORD flag,
    PFN_LoadLibraryA pfnLoadLibraryA, 
    PFN_GetProcAddress pfnGetProcAddress)
{
    // bind windows api
    char name_kernel32[] = { 'k', 'e', 'r', 'n', 'e', 'l', '3', '2', '.', 'd', 'l', 'l' , '\0'};
    char name_VirtualQuery[] = {'V', 'i', 'r', 't', 'u', 'a', 'l', 'Q', 'u', 'e', 'r', 'y', '\0'};
    char name_VirtualAlloc[] = {'V', 'i', 'r', 't', 'u', 'a', 'l', 'A', 'l', 'l', 'o', 'c', '\0'};
    char name_VirtualProtect[] = {'V', 'i', 'r', 't', 'u', 'a', 'l', 'P', 'r', 'o', 't', 'e', 'c', 't', '\0'};
    HMODULE hmod_kernel32 = pfnLoadLibraryA(name_kernel32);
    PFN_VirtualQuery pfnVirtualQuery = (PFN_VirtualQuery)
        pfnGetProcAddress(hmod_kernel32, name_VirtualQuery);
    PFN_VirtualAlloc pfnVirtualAlloc = (PFN_VirtualAlloc)
        pfnGetProcAddress(hmod_kernel32, name_VirtualAlloc);
    PFN_VirtualProtect pfnVirtualProtect =(PFN_VirtualProtect)
        pfnGetProcAddress(hmod_kernel32, name_VirtualProtect);
    assert(pfnVirtualQuery!=0 && pfnVirtualAlloc!=0 && pfnVirtualProtect!=0);

    // find proper imagebase
    size_t imagesize = winpe_imagesizeval(mempe, 0);
    if(flag & WINPE_LDFLAG_MEMFIND)
    {
        imagebase = winpe_imagebaseval(mempe, 0);
        imagebase = (size_t)winpe_findspace(imagebase,
            imagesize, 0x10000, pfnVirtualQuery);
    }
    if(flag & WINPE_LDFLAG_MEMALLOC) // find proper memory to reloc
    {

        imagebase = (size_t)pfnVirtualAlloc((void*)imagebase, 
            imagesize, MEM_COMMIT | MEM_RESERVE, 
            PAGE_EXECUTE_READWRITE);
        if(!imagebase) // try alloc in arbitary place
        {
            imagebase = (size_t)pfnVirtualAlloc(NULL, 
                imagesize, MEM_COMMIT, 
                PAGE_EXECUTE_READWRITE);
            if(!imagebase) return NULL;
        }
        else
        {
            imagebase = (size_t)pfnVirtualAlloc((void*)imagebase, 
                imagesize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
            if(!imagebase) return NULL;            
        }
    }

    // copy to imagebase
    if(!imagebase) 
    {
        imagebase = (size_t)mempe;
    }
    else
    {
        DWORD oldprotect;
        pfnVirtualProtect((void*)imagebase, imagesize, 
            PAGE_EXECUTE_READWRITE, &oldprotect);
        _winpeinl_memcpy((void*)imagebase, mempe, imagesize);
        pfnVirtualProtect((void*)imagebase, imagesize, 
            oldprotect, &oldprotect);
    }

    // initial memory module
    if(!winpe_memreloc((void*)imagebase, imagebase))
        return NULL;
    if(!winpe_membindiat((void*)imagebase, 
        pfnLoadLibraryA, pfnGetProcAddress)) return NULL;
    winpe_membindtls(mempe, DLL_PROCESS_ATTACH);
    PFN_DllMain pfnDllMain = (PFN_DllMain)
        (imagebase + winpe_oepval((void*)imagebase, 0));
    pfnDllMain((HINSTANCE)imagebase, DLL_PROCESS_ATTACH, NULL);
    return (void*)imagebase;
}

WINPEDEF WINPE_EXPORT
INLINE BOOL STDCALL winpe_memFreeLibrary(void *mempe)
{
    PFN_LoadLibraryA pfnLoadLibraryA = 
        (PFN_LoadLibraryA)winpe_findloadlibrarya();
    PFN_GetProcAddress pfnGetProcAddress = 
        (PFN_GetProcAddress)winpe_findgetprocaddress();
    return winpe_memFreeLibraryEx(mempe, 
        pfnLoadLibraryA, pfnGetProcAddress);
}

WINPEDEF WINPE_EXPORT
INLINE BOOL STDCALL winpe_memFreeLibraryEx(void *mempe, 
    PFN_LoadLibraryA pfnLoadLibraryA, 
    PFN_GetProcAddress pfnGetProcAddress)
{
    char name_kernel32[] = {'k', 'e', 'r', 'n', 'e', 'l', '3', '2', '\0'};
    char name_VirtualFree[] = {'V', 'i', 'r', 't', 'u', 'a', 'l', 'F', 'r', 'e', 'e', '\0'};
    HMODULE hmod_kernel32 = pfnLoadLibraryA(name_kernel32);
    PFN_VirtualFree pfnVirtualFree = (PFN_VirtualFree)
        pfnGetProcAddress(hmod_kernel32, name_VirtualFree);
    PFN_DllMain pfnDllMain = (PFN_DllMain)
        ((uint8_t*)mempe + winpe_oepval(mempe, 0));
    winpe_membindtls(mempe, DLL_PROCESS_DETACH);
    pfnDllMain((HINSTANCE)mempe, DLL_PROCESS_DETACH, NULL);
    return pfnVirtualFree(mempe, 0, MEM_FREE);
}

WINPEDEF WINPE_EXPORT
INLINE PROC STDCALL winpe_memGetProcAddress(
    void *mempe, const char *funcname)
{
    void* expva = winpe_memfindexp(mempe, funcname);
    size_t exprva = (size_t)((uint8_t*)expva - (uint8_t*)mempe);
    return (PROC)winpe_memforwardexp(mempe, exprva, // to avoid infinity loop
        (PFN_LoadLibraryA)winpe_findloadlibrarya(), 
        (PFN_GetProcAddress)winpe_findgetprocaddress());
}

// PE query functions
WINPEDEF WINPE_EXPORT
INLINE void* winpe_findkernel32()
{
    // return (void*)LoadLibrary("kernel32.dll");
    // TEB->PEB->Ldr->InMemoryOrderLoadList->curProgram->ntdll->kernel32
    void *kerenl32 = NULL;

#ifndef WINPE_NOASM
#ifdef _WIN64
    __asm{
        mov rax, gs:[60h]; peb
        mov rax, [rax+18h]; ldr
        mov rax, [rax+20h]; InMemoryOrderLoadList, currentProgramEntry
        mov rax, [rax]; ntdllEntry, currentProgramEntry->->Flink
        mov rax, [rax]; kernel32Entry,  ntdllEntry->Flink
        mov rax, [rax-10h+30h]; kernel32.DllBase
        mov kerenl32, rax;
    }
#else
    __asm{
        mov eax, fs:[30h]; peb
        mov eax, [eax+0ch]; ldr
        mov eax, [eax+14h]; InMemoryOrderLoadList, currentProgramEntry
        mov eax, [eax]; ntdllEntry, currentProgramEntry->->Flink
        mov eax, [eax]; kernel32Entry,  ntdllEntry->Flink
        mov eax, [eax - 8h +18h]; kernel32.DllBase
        mov kerenl32, eax;
    }
#endif
#else
    char name_kernel32[] = { 'k', 'e', 'r', 'n', 'e', 'l', '3', '2', '.', 'd', 'l', 'l' , '\0' };
    kerenl32 = winpe_findmodulea(name_kernel32);
#endif

    return kerenl32;
}

WINPEDEF WINPE_EXPORT
INLINE void* STDCALL winpe_findmoduleaex(
    PPEB peb, char *modulename)
{
    typedef struct _LDR_ENTRY  // has 3 kinds of pointer link list
    {
        LIST_ENTRY InLoadOrderLinks; // this has link pointer
        LIST_ENTRY InMemoryOrderLinks; // order is program, ntdll, kernel32.dll
        LIST_ENTRY InInitializationOrderLinks;//to next entry in same place
        PVOID DllBase; // 0x18, 0x30
        PVOID EntryPoint;
        ULONG SizeOfImage;
        UNICODE_STRING FullDllName;
        UNICODE_STRING BaseDllName;
        ULONG Flags;
        USHORT LoadCount;
        USHORT TlsIndex;
        union
        {
            LIST_ENTRY HashLinks;
            struct
            {
                PVOID SectionPointer;
                ULONG CheckSum;
            };
        };
        ULONG TimeDateStamp;
    } LDR_ENTRY, *PLDR_ENTRY; // use this because of mingw bug
    
    PLDR_ENTRY ldrentry = NULL;
    PPEB_LDR_DATA ldr = NULL;


    if(!peb)
    {
            PTEB teb = NtCurrentTeb(); 
#ifdef _WIN64
            peb = *(PPEB*)((uint8_t*)teb + 0x60);
#else
            peb = *(PPEB*)((uint8_t*)teb + 0x30);
#endif 
    }

#ifdef _WIN64
    ldr = *(PPEB_LDR_DATA*)((uint8_t*)peb + 0x18);
#else
    ldr = *(PPEB_LDR_DATA*)((uint8_t*)peb + 0xC);
#endif 

    // InMemoryOrderModuleList is the second entry
    ldrentry = (PLDR_ENTRY)((size_t)
        ldr->InMemoryOrderModuleList.Flink - 2*sizeof(size_t));
    if(!modulename)
    {
        return ldrentry->DllBase;
    }
    while(ldrentry->InMemoryOrderLinks.Flink != 
        ldr->InMemoryOrderModuleList.Flink)
    {
        PUNICODE_STRING ustr = &ldrentry->FullDllName;
        int i;
        for(i=ustr->Length/2-1; i>0 && ustr->Buffer[i]!='\\';i--);
        if(ustr->Buffer[i]=='\\') i++;
        if(_winpeinl_stricmp2(modulename,  ustr->Buffer + i)==0)
        {
            return ldrentry->DllBase;
        }
        ldrentry = (PLDR_ENTRY)((size_t)
            ldrentry->InMemoryOrderLinks.Flink - 2*sizeof(size_t));
    }
    return NULL;
}

WINPEDEF WINPE_EXPORT
INLINE PROC winpe_findloadlibrarya()
{
    // return (PROC)LoadLibraryA;
    HMODULE hmod_kernel32 = (HMODULE)winpe_findkernel32();
    char name_LoadLibraryA[] = {'L', 'o', 'a', 'd', 'L', 'i', 'b', 'r', 'a', 'r', 'y', 'A', '\0'};
    return (PROC)winpe_memfindexp( // suppose exp no forward, to avoid recursive
        (void*)hmod_kernel32, name_LoadLibraryA);
}

WINPEDEF WINPE_EXPORT
INLINE PROC winpe_findgetprocaddress()
{
    // return (PROC)GetProcAddress;
    HMODULE hmod_kernel32 = (HMODULE)winpe_findkernel32();
    char name_GetProcAddress[] = {'G', 'e', 't', 'P', 'r', 'o', 'c', 'A', 'd', 'd', 'r', 'e', 's', 's', '\0'};
    return (PROC)winpe_memfindexp(hmod_kernel32, name_GetProcAddress);
}

WINPEDEF WINPE_EXPORT
INLINE void* STDCALL winpe_findspace(
    size_t imagebase, size_t imagesize, size_t alignsize, 
    PFN_VirtualQuery pfnVirtualQuery)
{
#define MAX_QUERY 0x1000
    size_t addr = imagebase;
    MEMORY_BASIC_INFORMATION minfo;
    for (int i=0;i<MAX_QUERY;i++)
    {
        if(addr % alignsize) addr += 
            alignsize - addr% alignsize;
        pfnVirtualQuery((LPVOID)addr, 
            &minfo, sizeof(MEMORY_BASIC_INFORMATION));
        if(minfo.State==MEM_FREE 
            && minfo.RegionSize >= imagesize) 
            return (void*)addr;
        addr += minfo.RegionSize;
    }
    return NULL;
}

// PE load, adjust functions
WINPEDEF WINPE_EXPORT 
INLINE size_t STDCALL winpe_overlayoffset(const void *rawpe)
{
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)rawpe;
    PIMAGE_NT_HEADERS  pNtHeader = (PIMAGE_NT_HEADERS)
        ((uint8_t*)rawpe + pDosHeader->e_lfanew);
    PIMAGE_FILE_HEADER pFileHeader = &pNtHeader->FileHeader;
    PIMAGE_OPTIONAL_HEADER pOptHeader = &pNtHeader->OptionalHeader;
    PIMAGE_DATA_DIRECTORY pDataDirectory = pOptHeader->DataDirectory;
    PIMAGE_SECTION_HEADER pSectHeader = (PIMAGE_SECTION_HEADER)
        ((uint8_t*)pOptHeader + pFileHeader->SizeOfOptionalHeader);
    WORD sectNum = pFileHeader->NumberOfSections;

    return pSectHeader[sectNum-1].PointerToRawData + 
           pSectHeader[sectNum-1].SizeOfRawData;
}

WINPEDEF WINPE_EXPORT 
INLINE size_t STDCALL winpe_memload(
    const void *rawpe, size_t rawsize, 
    void *mempe, size_t memsize, 
    bool_t same_align)
{
    // load rawpe to memalign
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)rawpe;
    PIMAGE_NT_HEADERS  pNtHeader = (PIMAGE_NT_HEADERS)
        ((uint8_t*)rawpe + pDosHeader->e_lfanew);
    PIMAGE_FILE_HEADER pFileHeader = &pNtHeader->FileHeader;
    PIMAGE_OPTIONAL_HEADER pOptHeader = &pNtHeader->OptionalHeader;
    PIMAGE_SECTION_HEADER pSectHeader = (PIMAGE_SECTION_HEADER)
        ((uint8_t*)pOptHeader + pFileHeader->SizeOfOptionalHeader);
    WORD sectNum = pFileHeader->NumberOfSections;
    size_t imagesize = pOptHeader->SizeOfImage;
    if(!mempe) return imagesize;
    else if(memsize!=0 && memsize<imagesize) return 0;

    _winpeinl_memset(mempe, 0, imagesize);
    _winpeinl_memcpy(mempe, rawpe, pOptHeader->SizeOfHeaders);
    
    for(WORD i=0;i<sectNum;i++)
    {
        _winpeinl_memcpy((uint8_t*)mempe+pSectHeader[i].VirtualAddress,
            (uint8_t*)rawpe+pSectHeader[i].PointerToRawData,
            pSectHeader[i].SizeOfRawData);
    }

    // adjust all to mem align
    if(same_align)
    {
        pDosHeader = (PIMAGE_DOS_HEADER)mempe;
        pNtHeader = (PIMAGE_NT_HEADERS)((uint8_t*)mempe + pDosHeader->e_lfanew);
        pFileHeader = &pNtHeader->FileHeader;
        pOptHeader = &pNtHeader->OptionalHeader;
        pSectHeader = (PIMAGE_SECTION_HEADER)
            ((uint8_t*)pOptHeader + pFileHeader->SizeOfOptionalHeader);
        sectNum = pFileHeader->NumberOfSections;

        pOptHeader->FileAlignment = pOptHeader->SectionAlignment;

        for(WORD i=0;i<sectNum;i++)
        {
            pSectHeader[i].PointerToRawData = pSectHeader[i].VirtualAddress;
        }
    }
    return imagesize;
}

WINPEDEF WINPE_EXPORT 
INLINE size_t STDCALL winpe_memreloc(
    void *mempe, size_t newimagebase)
{
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)mempe;
    PIMAGE_NT_HEADERS  pNtHeader = (PIMAGE_NT_HEADERS)
        ((uint8_t*)mempe + pDosHeader->e_lfanew);
    PIMAGE_FILE_HEADER pFileHeader = &pNtHeader->FileHeader;
    PIMAGE_OPTIONAL_HEADER pOptHeader = &pNtHeader->OptionalHeader;
    PIMAGE_DATA_DIRECTORY pDataDirectory = pOptHeader->DataDirectory;
    PIMAGE_DATA_DIRECTORY pRelocEntry = &pDataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	
    DWORD reloc_count = 0;
    DWORD reloc_offset = 0;
    int64_t shift = (int64_t)newimagebase - 
        (int64_t)pOptHeader->ImageBase;
	while (reloc_offset < pRelocEntry->Size)
	{
		PIMAGE_BASE_RELOCATION pBaseReloc = (PIMAGE_BASE_RELOCATION)
            ((uint8_t*)mempe + pRelocEntry->VirtualAddress + reloc_offset);
        PRELOCOFFSET pRelocOffset = (PRELOCOFFSET)((uint8_t*)pBaseReloc
            + sizeof(IMAGE_BASE_RELOCATION));
		DWORD item_num = (pBaseReloc->SizeOfBlock - // RELOCOFFSET block num
			sizeof(IMAGE_BASE_RELOCATION)) / sizeof(RELOCOFFSET);
		for (size_t i = 0; i < item_num; i++)
		{
			if (!pRelocOffset[i].type && 
                !pRelocOffset[i].offset) continue;
			DWORD targetoffset = pBaseReloc->VirtualAddress + 
                    pRelocOffset[i].offset;
            size_t *paddr = (size_t *)((uint8_t*)mempe + targetoffset);
            size_t relocaddr = (size_t)((int64_t)*paddr + shift);
            //printf("reloc 0x%08x->0x%08x\n", *paddr, relocaddr);
            *paddr = relocaddr;
		}
		reloc_offset += sizeof(IMAGE_BASE_RELOCATION) + 
            sizeof(RELOCOFFSET) * item_num;
		reloc_count += item_num;
	}
    pOptHeader->ImageBase = newimagebase;
	return reloc_count;
}

WINPEDEF WINPE_EXPORT 
INLINE size_t STDCALL winpe_membindiat(void *mempe, 
    PFN_LoadLibraryA pfnLoadLibraryA, 
    PFN_GetProcAddress pfnGetProcAddress)
{
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)mempe;
    PIMAGE_NT_HEADERS  pNtHeader = (PIMAGE_NT_HEADERS)
        ((uint8_t*)mempe + pDosHeader->e_lfanew);
    PIMAGE_FILE_HEADER pFileHeader = &pNtHeader->FileHeader;
    PIMAGE_OPTIONAL_HEADER pOptHeader = &pNtHeader->OptionalHeader;
    PIMAGE_DATA_DIRECTORY pDataDirectory = pOptHeader->DataDirectory;
    PIMAGE_DATA_DIRECTORY pImpEntry =  
        &pDataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    PIMAGE_IMPORT_DESCRIPTOR pImpDescriptor =  
        (PIMAGE_IMPORT_DESCRIPTOR)((uint8_t*)mempe + pImpEntry->VirtualAddress);

    PIMAGE_THUNK_DATA pFtThunk = NULL;
    PIMAGE_THUNK_DATA pOftThunk = NULL;
    LPCSTR pDllName = NULL;
    PIMAGE_IMPORT_BY_NAME pImpByName = NULL;
    size_t funcva = 0;
    char *funcname = NULL;

    // origin GetProcAddress will crash at InitializeSListHead 
    if(!pfnLoadLibraryA) pfnLoadLibraryA = 
        (PFN_LoadLibraryA)winpe_findloadlibrarya();
    if(!pfnGetProcAddress) pfnGetProcAddress = 
        (PFN_GetProcAddress)winpe_findgetprocaddress();

    DWORD iat_count = 0;
    for (; pImpDescriptor->Name; pImpDescriptor++) 
    {
        pDllName = (LPCSTR)((uint8_t*)mempe + pImpDescriptor->Name);
        pFtThunk = (PIMAGE_THUNK_DATA)
            ((uint8_t*)mempe + pImpDescriptor->FirstThunk);
        pOftThunk = (PIMAGE_THUNK_DATA)
            ((uint8_t*)mempe + pImpDescriptor->OriginalFirstThunk);
        size_t dllbase = (size_t)pfnLoadLibraryA(pDllName);
        if(!dllbase) return 0;

        for (int j=0; pFtThunk[j].u1.Function 
            &&  pOftThunk[j].u1.Function; j++) 
        {
            size_t _addr = (size_t)((uint8_t*)mempe + pOftThunk[j].u1.AddressOfData);
            if(sizeof(size_t)>4) // x64
            {
                if(((uint64_t)_addr>>63) == 1)
                {
                    funcname = (char *)(_addr & 0x000000000000ffff);
                }
                else
                {
                    pImpByName=(PIMAGE_IMPORT_BY_NAME)_addr;
                    funcname = pImpByName->Name;
                }
            }
            else
            {
                if(((size_t)pImpByName>>31) == 1)
                {
                    funcname = (char *)(_addr & 0x0000ffff);
                }
                else
                {
                    pImpByName=(PIMAGE_IMPORT_BY_NAME)_addr;
                    funcname = pImpByName->Name;
                }
            }

            funcva = (size_t)pfnGetProcAddress(
                (HMODULE)dllbase, funcname);
            if(!funcva) continue;
            pFtThunk[j].u1.Function = funcva;
            assert(funcva == (size_t)GetProcAddress(
                (HMODULE)dllbase, funcname));
            iat_count++;
        }
    }
    return iat_count;
}

WINPEDEF WINPE_EXPORT 
INLINE size_t STDCALL winpe_membindtls(void *mempe, DWORD reason)
{
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)mempe;
    PIMAGE_NT_HEADERS  pNtHeader = (PIMAGE_NT_HEADERS)
        ((uint8_t*)mempe + pDosHeader->e_lfanew);
    PIMAGE_FILE_HEADER pFileHeader = &pNtHeader->FileHeader;
    PIMAGE_OPTIONAL_HEADER pOptHeader = &pNtHeader->OptionalHeader;
    PIMAGE_DATA_DIRECTORY pDataDirectory = pOptHeader->DataDirectory;
    PIMAGE_DATA_DIRECTORY pTlsDirectory = 
        &pDataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
    if(!pTlsDirectory->VirtualAddress) return 0;

    size_t tls_count = 0;
    PIMAGE_TLS_DIRECTORY pTlsEntry = (PIMAGE_TLS_DIRECTORY)
        ((uint8_t*)mempe + pTlsDirectory->VirtualAddress);
    PIMAGE_TLS_CALLBACK *tlscb= (PIMAGE_TLS_CALLBACK*)
        pTlsEntry->AddressOfCallBacks;
    if(tlscb)
    {
        while(*tlscb)
        {
            (*tlscb)(mempe, reason, NULL);
            tlscb++;
            tls_count++;
        }
    }
    return tls_count;
}

WINPEDEF WINPE_EXPORT
INLINE void* STDCALL winpe_memfindiat(void *mempe, 
    LPCSTR dllname, LPCSTR funcname)
{
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)mempe;
    PIMAGE_NT_HEADERS  pNtHeader = (PIMAGE_NT_HEADERS)
        ((uint8_t*)mempe + pDosHeader->e_lfanew);
    PIMAGE_FILE_HEADER pFileHeader = &pNtHeader->FileHeader;
    PIMAGE_OPTIONAL_HEADER pOptHeader = &pNtHeader->OptionalHeader;
    PIMAGE_DATA_DIRECTORY pDataDirectory = pOptHeader->DataDirectory;
    PIMAGE_DATA_DIRECTORY pImpEntry =  
        &pDataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    PIMAGE_IMPORT_DESCRIPTOR pImpDescriptor =  
        (PIMAGE_IMPORT_DESCRIPTOR)((uint8_t*)mempe + pImpEntry->VirtualAddress);

    PIMAGE_THUNK_DATA pFtThunk = NULL;
    PIMAGE_THUNK_DATA pOftThunk = NULL;
    LPCSTR pDllName = NULL;
    PIMAGE_IMPORT_BY_NAME pImpByName = NULL;

    for (; pImpDescriptor->Name; pImpDescriptor++) 
    {
        pDllName = (LPCSTR)((uint8_t*)mempe + pImpDescriptor->Name);
        if(dllname && _winpeinl_stricmp(pDllName, dllname)!=0) continue;
        pFtThunk = (PIMAGE_THUNK_DATA)
            ((uint8_t*)mempe + pImpDescriptor->FirstThunk);
        pOftThunk = (PIMAGE_THUNK_DATA)
            ((uint8_t*)mempe + pImpDescriptor->OriginalFirstThunk);

        for (int j=0; pFtThunk[j].u1.Function 
            &&  pOftThunk[j].u1.Function; j++) 
        {
            pImpByName=(PIMAGE_IMPORT_BY_NAME)((uint8_t*)mempe +
                pOftThunk[j].u1.AddressOfData);
            if((size_t)funcname < MAXWORD) // ordinary
            {
                WORD funcord = LOWORD(funcname);
                if(pImpByName->Hint == funcord)
                    return &pFtThunk[j];
            }
            else
            {
                if(_winpeinl_stricmp(pImpByName->Name, funcname)==0) 
                    return &pFtThunk[j];
            }
        }
    }
    return 0;
}

WINPEDEF WINPE_EXPORT 
INLINE void* STDCALL winpe_memfindexp(
    void *mempe, LPCSTR funcname)
{
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)mempe;
    PIMAGE_NT_HEADERS  pNtHeader = (PIMAGE_NT_HEADERS)
        ((uint8_t*)mempe + pDosHeader->e_lfanew);
    PIMAGE_FILE_HEADER pFileHeader = &pNtHeader->FileHeader;
    PIMAGE_OPTIONAL_HEADER pOptHeader = &pNtHeader->OptionalHeader;
    PIMAGE_DATA_DIRECTORY pDataDirectory = pOptHeader->DataDirectory;
    PIMAGE_DATA_DIRECTORY pExpEntry =  
        &pDataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    PIMAGE_EXPORT_DIRECTORY  pExpDescriptor =  
        (PIMAGE_EXPORT_DIRECTORY)((uint8_t*)mempe + pExpEntry->VirtualAddress);

    WORD *ordrva = (WORD*)((uint8_t*)mempe 
        + pExpDescriptor->AddressOfNameOrdinals);
    DWORD *namerva = (DWORD*)((uint8_t*)mempe 
        + pExpDescriptor->AddressOfNames);
    DWORD *funcrva = (DWORD*)((uint8_t*)mempe 
        + pExpDescriptor->AddressOfFunctions);
    if((size_t)funcname <= MAXWORD) // find by ordnial
    {
        WORD ordbase = LOWORD(pExpDescriptor->Base) - 1;
        WORD funcord = LOWORD(funcname);
        return (void*)((uint8_t*)mempe + funcrva[ordrva[funcord-ordbase]]);
    }
    else
    {
        for(DWORD i=0;i<pExpDescriptor->NumberOfNames;i++)
        {
            LPCSTR curname = (LPCSTR)((uint8_t*)mempe+namerva[i]);
            if(_winpeinl_stricmp(curname, funcname)==0)
            {
                return (void*)((uint8_t*)mempe + funcrva[ordrva[i]]);
            }       
        }
    }
    return NULL;
}

WINPEDEF WINPE_EXPORT
INLINE void* STDCALL winpe_memfindexpcrc32(
    void* mempe, uint32_t crc32)
{
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)mempe;
    PIMAGE_NT_HEADERS  pNtHeader = (PIMAGE_NT_HEADERS)
        ((uint8_t*)mempe + pDosHeader->e_lfanew);
    PIMAGE_FILE_HEADER pFileHeader = &pNtHeader->FileHeader;
    PIMAGE_OPTIONAL_HEADER pOptHeader = &pNtHeader->OptionalHeader;
    PIMAGE_DATA_DIRECTORY pDataDirectory = pOptHeader->DataDirectory;
    PIMAGE_DATA_DIRECTORY pExpEntry =
        &pDataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    PIMAGE_EXPORT_DIRECTORY  pExpDescriptor =
        (PIMAGE_EXPORT_DIRECTORY)((uint8_t*)mempe + pExpEntry->VirtualAddress);

    WORD* ordrva = (WORD*)((uint8_t*)mempe
        + pExpDescriptor->AddressOfNameOrdinals);
    DWORD* namerva = (DWORD*)((uint8_t*)mempe
        + pExpDescriptor->AddressOfNames);
    DWORD* funcrva = (DWORD*)((uint8_t*)mempe
        + pExpDescriptor->AddressOfFunctions);
    for (DWORD i = 0; i < pExpDescriptor->NumberOfNames; i++)
    {
        LPCSTR curname = (LPCSTR)((uint8_t*)mempe + namerva[i]);
        if (crc32==_winpeinl_crc32(curname, _winpeinl_strlen(curname)))
        {
            return (void*)((uint8_t*)mempe + funcrva[ordrva[i]]);
        }
    }
    return NULL;
}

WINPEDEF WINPE_EXPORT
INLINE void* STDCALL winpe_memforwardexp(
    void *mempe, size_t exprva, 
    PFN_LoadLibraryA pfnLoadLibraryA, 
    PFN_GetProcAddress pfnGetProcAddress)
{
    // this function might have infinite loop
    // such as this situation
    // kerenl32.dll, GetProcessMitigationPolicy -> api-ms-win-core-processthreads-l1-1-1.dll -> kerenl32.dll, GetProcessMitigationPolicys
    size_t dllbase = (size_t)mempe;
    while (1)
    {
        PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)dllbase;
        PIMAGE_NT_HEADERS  pNtHeader = (PIMAGE_NT_HEADERS)
            ((uint8_t*)dllbase + pDosHeader->e_lfanew);
        PIMAGE_OPTIONAL_HEADER pOptHeader = &pNtHeader->OptionalHeader;
        PIMAGE_DATA_DIRECTORY pDataDirectory = pOptHeader->DataDirectory;
        PIMAGE_DATA_DIRECTORY pExpEntry =  
            &pDataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        if(exprva>=pExpEntry->VirtualAddress && 
            exprva<= pExpEntry->VirtualAddress + pExpEntry->Size)
        {
            char namebuf[MAX_PATH];
            char *dllname = (char *)(dllbase + exprva);
            char *funcname = dllname;
            int i=0, j=0;
            while(dllname[i]!=0)
            {
                if(dllname[i]=='.')
                {
                    namebuf[j] = dllname[i];
                    namebuf[++j] = 'd';
                    namebuf[++j] = 'l';
                    namebuf[++j] = 'l';
                    namebuf[++j] = '\0';
                    funcname = namebuf + j + 1;
                }
                else
                {
                    namebuf[j]=dllname[i];
                }
                i++;
                j++;
            }
            namebuf[j] = '\0';
            dllname = namebuf;
            dllbase = (size_t)pfnLoadLibraryA(dllname);
            exprva = (size_t)pfnGetProcAddress((HMODULE)dllbase, funcname);
            exprva -= dllbase;
        }
        else
        {
            return (void*)(dllbase + exprva);
        } 
    }
    return NULL;
}

// PE setting function
WINPEDEF WINPE_EXPORT
INLINE void STDCALL winpe_noaslr(void *pe)
{
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pe;
    PIMAGE_NT_HEADERS  pNtHeader = (PIMAGE_NT_HEADERS)
        ((uint8_t*)pe + pDosHeader->e_lfanew);
    PIMAGE_FILE_HEADER pFileHeader = &pNtHeader->FileHeader;
    PIMAGE_OPTIONAL_HEADER pOptHeader = &pNtHeader->OptionalHeader;
    #ifndef IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE
    #define IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE 0x0040
    #endif
    pOptHeader->DllCharacteristics &= ~IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE;
}

WINPEDEF WINPE_EXPORT
INLINE DWORD STDCALL winpe_oepval(void *pe, DWORD newoeprva)
{
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pe;
    PIMAGE_NT_HEADERS  pNtHeader = (PIMAGE_NT_HEADERS)
        ((uint8_t*)pe + pDosHeader->e_lfanew);
    PIMAGE_FILE_HEADER pFileHeader = &pNtHeader->FileHeader;
    PIMAGE_OPTIONAL_HEADER pOptHeader = &pNtHeader->OptionalHeader;
    DWORD orgoep = pOptHeader->AddressOfEntryPoint;
    if(newoeprva) pOptHeader->AddressOfEntryPoint = newoeprva;
    return orgoep;
}

WINPEDEF WINPE_EXPORT
INLINE size_t STDCALL winpe_imagebaseval(void *pe, size_t newimagebase)
{
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pe;
    PIMAGE_NT_HEADERS  pNtHeader = (PIMAGE_NT_HEADERS)
        ((uint8_t*)pe + pDosHeader->e_lfanew);
    PIMAGE_FILE_HEADER pFileHeader = &pNtHeader->FileHeader;
    PIMAGE_OPTIONAL_HEADER pOptHeader = &pNtHeader->OptionalHeader;
    size_t imagebase = pOptHeader->ImageBase;
    if(newimagebase) pOptHeader->ImageBase = newimagebase;
    return imagebase; 
}

WINPEDEF WINPE_EXPORT
INLINE size_t STDCALL winpe_imagesizeval(void *pe, size_t newimagesize)
{
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pe;
    PIMAGE_NT_HEADERS  pNtHeader = (PIMAGE_NT_HEADERS)
        ((uint8_t*)pe + pDosHeader->e_lfanew);
    PIMAGE_FILE_HEADER pFileHeader = &pNtHeader->FileHeader;
    PIMAGE_OPTIONAL_HEADER pOptHeader = &pNtHeader->OptionalHeader;
    size_t imagesize = pOptHeader->SizeOfImage;
    if(newimagesize) pOptHeader->SizeOfImage = (DWORD)newimagesize;
    return imagesize; 
}

WINPEDEF WINPE_EXPORT 
INLINE size_t STDCALL winpe_appendsecth(void *pe, 
    PIMAGE_SECTION_HEADER psecth)
{
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pe;
    PIMAGE_NT_HEADERS  pNtHeader = (PIMAGE_NT_HEADERS)
        ((uint8_t*)pe + pDosHeader->e_lfanew);
    PIMAGE_FILE_HEADER pFileHeader = &pNtHeader->FileHeader;
    PIMAGE_OPTIONAL_HEADER pOptHeader = &pNtHeader->OptionalHeader;
    PIMAGE_SECTION_HEADER pSectHeader = (PIMAGE_SECTION_HEADER)
        ((uint8_t*)pOptHeader + pFileHeader->SizeOfOptionalHeader);
    WORD sectNum = pFileHeader->NumberOfSections;
    PIMAGE_SECTION_HEADER pLastSectHeader = &pSectHeader[sectNum-1];
    DWORD addr, align;

    // check the space to append section
    if(pFileHeader->SizeOfOptionalHeader 
        + sizeof(IMAGE_SECTION_HEADER)
     > pSectHeader[0].PointerToRawData) return 0;

    // fill rva addr
    align = pOptHeader->SectionAlignment;
    addr = pLastSectHeader->VirtualAddress + pLastSectHeader->Misc.VirtualSize;
    if(addr % align) addr += align - addr%align;
    psecth->VirtualAddress = addr;

    // fill file offset
    align = pOptHeader->FileAlignment;
    addr =  pLastSectHeader->PointerToRawData+ pLastSectHeader->SizeOfRawData;
    if(addr % align) addr += align - addr%align;
    psecth->PointerToRawData = addr;

    // adjust the section and imagesize 
    pFileHeader->NumberOfSections++;
    _winpeinl_memcpy(&pSectHeader[sectNum], psecth, sizeof(IMAGE_SECTION_HEADER));
    align = pOptHeader->SectionAlignment;
    addr = psecth->VirtualAddress + psecth->Misc.VirtualSize;
    if(addr % align) addr += align - addr%align;
    pOptHeader->SizeOfImage = addr; 
    return pOptHeader->SizeOfImage;
}

#endif
#endif

/*
history:
v0.1, initial version, with load pe in memory align
V0.1.2, adjust declear name, load pe iat
v0.2, add append section, findiat function
v0.2.2, add function winpe_memfindexp
v0.2.5, INLINE basic functions, better for shellcode
v0.3, add winpe_memloadlibrary, winpe_memGetprocaddress, winpe_memFreelibrary
v0.3.1, fix the stdcall function name by .def, load memory moudule aligned with 0x1000(x86), 0x10000(x64)
v0.3.2, x64 memory load support, winpe_findkernel32, winpe_finmodule by asm
v0.3.3, add ordinal support in winpe_membindiat, add win_membindtls, change all call to STDCALL
v0.3.4, add WINPE_NOASM to make compatible for vs x64
v0.3.5, add winpe_memfindexpcrc32
*/