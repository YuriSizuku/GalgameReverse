/**
 * windows dyamic hook util functions wrappers
 *   v0.3.1, developed by devseed
*/

#ifndef _WINHOOK_H
#define _WINHOOK_H
#define WINHOOK_VERSION 310

#include <windows.h>

#ifndef WINHOOKDEF
#ifdef WINHOOK_STATIC
#define WINHOOKDEF static
#else
#define WINHOOKDEF extern
#endif
#endif

#ifndef WINHOOK_SHARED
#define WINHOOK_EXPORT
#else
#ifdef _WIN32
#define WINHOOK_EXPORT __declspec(dllexport)
#else
#define WINHOOK_EXPORT __attribute__((visibility("default")))
#endif
#endif

#ifndef INLINE
#ifdef WINHOOK_USESHELLCODE
#if defined(_MSC_VER)
#define INLINE __forceinline
#else  // tcc, gcc not support inline export ...
#define INLINE
#endif
#else
#define INLINE
#endif
#endif

#ifdef __cplusplus
extern "C" {
#endif
// loader functions
/**
 * start a exe and inject dll into exe
 * return pid
*/
WINHOOKDEF WINHOOK_EXPORT
INLINE DWORD winhook_startexeinject(LPCSTR exepath,
    LPSTR cmdstr, LPCSTR dllpath);

/**
 * start a exe by CreateProcess
 * @return pid
*/
#define winhook_startexe(exepath, cmdstr)\
    winhook_startexeinject(exepath, cmdstr, NULL)


/**
 * get the process handle by exename
*/
WINHOOKDEF WINHOOK_EXPORT 
INLINE HANDLE winhook_getprocess(LPCWSTR exename);

/**
 * get the other process image base
*/
WINHOOKDEF WINHOOK_EXPORT
INLINE size_t winhook_getimagebase(HANDLE hprocess);

/**
 * dynamic inject a dll into a process
*/ 
WINHOOKDEF WINHOOK_EXPORT 
INLINE BOOL winhook_injectdll(HANDLE hprocess, LPCSTR dllname);

/**
 * alloc a console for the program
*/
WINHOOKDEF WINHOOK_EXPORT 
INLINE void winhook_installconsole();


// dynamic hook functions
/**
 * patch addr by buf with bufsize
*/
WINHOOKDEF WINHOOK_EXPORT
INLINE BOOL winhook_patchmemoryex(HANDLE hprocess,
    LPVOID addr, const void* buf, size_t bufsize);

#define winhook_patchmemory(addr, buf, bufsize)\
    winhook_patchmemoryex(GetCurrentProcess(), addr, buf, bufsize)

/**
 * batch patch memories
*/
WINHOOKDEF WINHOOK_EXPORT
INLINE BOOL winhook_patchmemorysex(HANDLE hprocess,
    LPVOID addrs[], void* bufs[], 
    size_t bufsizes[], int n);

#define winhook_patchmemorys(addrs, bufs, bufsizes, n)\
    winhook_patchmemorysex(GetCurrentProcess(), addrs, bufs, bufsizes, n)

/**
 * patch memory with pattern, 
 * @param pattern
 *   skip '#' line, + for reative address, then multi byte code (hex) 
 *   00400000: ff 90
 *   +3f00: 90 90 90 90
 *   +3f06: 90; +3f08: 90
 * @return patch bytes number, error < 0
*/
WINHOOKDEF WINHOOK_EXPORT
INLINE int winhook_patchmemorypattern(const char *pattern);

/**
 * patch memory with pattern 1337 by x64dbg, use rva
 * can use ';' instead of '\r' '\n'
*/
WINHOOKDEF WINHOOK_EXPORT
INLINE int winhook_patchmemory1337ex(HANDLE hprocess, const char* pattern, size_t base, BOOL revert);

#define winhook_patchmemory1337(pattern, base, revert) \
    winhook_patchmemory1337ex(GetCurrentProcess(), pattern, base, revert)

/**
 * patch memory with pattern ips(International Patching System)
 * specifications at https://zerosoft.zophar.net/ips.php
 * addr is relative to base, big endian
*/
WINHOOKDEF WINHOOK_EXPORT
INLINE int winhook_patchmemoryipsex(HANDLE hprocess, const char* pattern, size_t base);

#define winhook_patchmemoryips(pattern, base) \
    winhook_patchmemoryipsex(GetCurrentProcess(), pattern, base)

/**
 * search the pattern like "ab 12 ?? 34"
 * @return the matched address
*/
WINHOOKDEF WINHOOK_EXPORT
INLINE void* winhook_searchmemory(void* addr, size_t memsize,
    const char* pattern, size_t *pmatchsize);

WINHOOKDEF WINHOOK_EXPORT
INLINE void* winhook_searchmemoryex(HANDLE hprocess,
    void* addr, size_t memsize,
    const char* pattern, size_t* pmatchsize);

/**
 * winhook_iathookmodule is for windows dll, 
 * @param moduleDllName is which dll to hook iat
*/
WINHOOKDEF WINHOOK_EXPORT
INLINE BOOL winhook_iathookpe(LPCSTR targetDllName,
    void* mempe, PROC pfnOrg, PROC pfnNew);

#define winhook_iathookmodule(targetDllName, moduleDllName, pfnOrg, pfnNew)\
    winhook_iathookpe(targetDllName, GetModuleHandle(moduleDllName), pfnOrg, pfnNew)

/**
 * iat dynamiclly hook, 
 * replace the @param pfgNew with @param pfnOrg function 
 * @param targetDllName like "user32.dll", "kernel32.dll"
*/
#define winhook_iathook(targetDllName, pfnOrg, pfgNew)\
    winhook_iathookmodule(targetDllName, NULL, pfnOrg, pfgNew)

/**
 * inline hooks wrapper, 
 * @param pfnTargets -> @param pfnNews, save origin pointers in @param pfnOlds
 * @return: success hook numbers
*/
WINHOOKDEF WINHOOK_EXPORT
int winhook_inlinehooks(PVOID pfnTargets[],
    PVOID pfnNews[], PVOID pfnOlds[], size_t n);

WINHOOKDEF WINHOOK_EXPORT
int winhook_inlineunhooks(PVOID pfnTargets[],
    PVOID pfnNews[], PVOID pfnOlds[], size_t n);

#endif 

#ifdef __cplusplus
}
#endif

#ifdef WINHOOK_IMPLEMENTATION
#include <stdio.h>
#include <stdint.h>
#include <windows.h>
#include <winternl.h>
#include <tlhelp32.h>
#include <psapi.h>

#ifdef WINHOOK_USESHELLCODE
#define WINDYN_IMPLEMENTATION
#define WINDYN_STATIC
#include "windyn.h"
#define strlen windyn_strlen
#define _stricmp windyn_stricmp
#define _wcsicmp windyn_wcsicmp
#define GetModuleHandleA windyn_GetModuleHandleA
#define LoadLibraryA windyn_LoadLibraryA
#define GetProcAddress windyn_GetProcAddress
#define VirtualAllocEx windyn_VirtualAllocEx
#endif

// loader functions
WINHOOKDEF WINHOOK_EXPORT
INLINE DWORD winhook_startexeinject(LPCSTR exepath,
    LPSTR cmdstr, LPCSTR dllpath)
{
    STARTUPINFOA si = {0};
    PROCESS_INFORMATION pi = {0};
    si.cb = sizeof(STARTUPINFOA);
    if (!CreateProcessA(exepath, cmdstr,
        NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi))
        return 0;

    if (dllpath) // inject dll to process
    {
        size_t n = 0;
        HANDLE hprocess = pi.hProcess;
        HANDLE hthread = pi.hThread;
        LPVOID injectaddr = VirtualAllocEx(hprocess,
            0, 0x1000, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        size_t oepva = 0;

        // prepare shellcode 
        CONTEXT context = { 0 };
        context.ContextFlags = CONTEXT_ALL;
        GetThreadContext(hthread, &context);
#ifdef _WIN64
        uint8_t injectcode[] = {0x50,0x53,0x51,0x52,0xe8,0x2d,0x00,0x00,0x00,0x48,0x8d,0x58,0xf7,0x48,0x83,0xec,0x28,0x48,0x8b,0x8b,0x43,0x00,0x00,0x00,0x48,0x8b,0x83,0x4b,0x00,0x00,0x00,0xff,0xd0,0x48,0x83,0xc4,0x28,0x48,0x8b,0x83,0x3b,0x00,0x00,0x00,0x49,0x89,0xc7,0x5a,0x59,0x5b,0x58,0x41,0xff,0xe7,0x48,0x8b,0x04,0x24,0xc3,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90 };
        oepva = context.Rip; 
        context.Rip = (ULONGLONG)injectaddr;

#else
        uint8_t injectcode[] = {0x50,0x53,0xe8,0x1e,0x00,0x00,0x00,0x8d,0x58,0xf9,0x8b,0x83,0x2d,0x00,0x00,0x00,0x50,0x8b,0x83,0x31,0x00,0x00,0x00,0xff,0xd0,0x8b,0x83,0x29,0x00,0x00,0x00,0x89,0xc7,0x5b,0x58,0xff,0xe7,0x8b,0x04,0x24,0xc3,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90 };
        oepva = context.Eip; // origin eip at RtlUserThreadStart
        context.Eip = (DWORD)injectaddr; 
#endif
        SetThreadContext(hthread, &context);

        char name_kernel32[] = { 'k', 'e', 'r', 'n', 'e', 'l', '3', '2', '.', 'd', 'l', 'l', '\0'};
        HMODULE kernel32 = GetModuleHandleA(name_kernel32);
        char name_LoadLibraryA[] = { 'L', 'o', 'a', 'd', 'L', 'i', 'b', 'r', 'a', 'r', 'y', 'A', '\0' };
        FARPROC pfnLoadlibraryA = GetProcAddress(kernel32, name_LoadLibraryA);
        size_t* pretva = (size_t*)(injectcode 
            + sizeof(injectcode) - 3 * sizeof(size_t));
        size_t *pdllnameva = (size_t*)(injectcode 
            + sizeof(injectcode) - 2 * sizeof(size_t));
        size_t* ploadlibraryva = (size_t*)(injectcode 
            + sizeof(injectcode) - 1 * sizeof(size_t));
        *pretva = (size_t)oepva;
        *pdllnameva = (size_t)((size_t)injectaddr + sizeof(injectcode));
        *ploadlibraryva = (size_t)pfnLoadlibraryA;

        uint8_t* addr = (uint8_t*)injectaddr;
        WriteProcessMemory(hprocess, addr,
            injectcode, sizeof(injectcode), (SIZE_T*)&n); // copy shellcode
        addr += sizeof(injectcode);
        WriteProcessMemory(hprocess, addr,
            dllpath, strlen(dllpath) + 1, (SIZE_T*)&n); // copy dll name
    }

    ResumeThread(pi.hThread);
    CloseHandle(pi.hThread);
    return pi.dwProcessId;
}

WINHOOKDEF WINHOOK_EXPORT 
INLINE HANDLE winhook_getprocess(LPCWSTR exename)
{
    // Create toolhelp snapshot.
    DWORD pid = 0;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 process;
    ZeroMemory(&process, sizeof(process));
    process.dwSize = sizeof(process);

    // Walkthrough all processes.
    if (Process32First(snapshot, &process))
    {
        do
        {
            if (_wcsicmp((const wchar_t*)process.szExeFile, exename) == 0)
            {
                pid = process.th32ProcessID;
                break;
            }
        } while (Process32Next(snapshot, &process));
    }
    CloseHandle(snapshot);
    if (pid != 0) return OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    return NULL; // Not found
}

WINHOOKDEF WINHOOK_EXPORT
INLINE size_t winhook_getimagebase(HANDLE hprocess)
{
    //if (hprocess == GetCurrentProcess()) return (size_t)GetModuleHandleA(NULL);
    HMODULE modules[1024]; // Array that receives the list of module handles
    DWORD nmodules = 0;
    char modulename[MAX_PATH] = {0};
    if (!EnumProcessModules(hprocess, modules, sizeof(modules), &nmodules)) 
        return 0; // impossible to read modules
    if (!GetModuleFileNameExA(hprocess, modules[0], modulename, sizeof(modulename))) 
        return 0; // impossible to get module info
    return (size_t)modules[0]; // module 0 is apparently always the EXE itself
}

WINHOOKDEF WINHOOK_EXPORT
INLINE BOOL winhook_injectdll(HANDLE hprocess, LPCSTR dllname)
{
    LPVOID addr = VirtualAllocEx(hprocess, 
        0, 0x100, MEM_COMMIT, PAGE_READWRITE);
    SIZE_T count;
    if (addr == NULL) return FALSE;
    WriteProcessMemory(hprocess, 
        addr, dllname, strlen(dllname)+1, (SIZE_T*)&count);

    char name_kernel32[] = { 'k', 'e', 'r', 'n', 'e', 'l', '3', '2', '.', 'd', 'l', 'l', '\0' };
    HMODULE kernel32 = GetModuleHandleA(name_kernel32);
    char name_LoadLibraryA[] = { 'L', 'o', 'a', 'd', 'L', 'i', 'b', 'r', 'a', 'r', 'y', 'A', '\0' };
    FARPROC pfnLoadlibraryA = GetProcAddress(kernel32, name_LoadLibraryA);
    HANDLE hthread = CreateRemoteThread(hprocess, NULL, 0, 
        (LPTHREAD_START_ROUTINE)pfnLoadlibraryA, addr, 0, NULL); 
   
    if (hthread == NULL) return FALSE;
    WaitForSingleObject(hthread, -1);
    VirtualFreeEx(hprocess, addr, 0x100, MEM_COMMIT);

    return TRUE;
}

WINHOOKDEF WINHOOK_EXPORT 
INLINE void winhook_installconsole()
{
    AllocConsole();
    freopen("CONOUT$", "w", stdout);    
}

// dynamic hook functions
WINHOOKDEF WINHOOK_EXPORT
INLINE BOOL winhook_patchmemoryex(HANDLE hprocess,
    LPVOID addr, const void* buf, size_t bufsize)
{
    if (addr == NULL || buf == NULL) return FALSE;
    DWORD oldprotect;
    BOOL ret = VirtualProtectEx(hprocess, addr,
        bufsize, PAGE_EXECUTE_READWRITE, &oldprotect);
    if (ret)
    {
        size_t n = 0;
        WriteProcessMemory(hprocess, addr, 
            buf, bufsize, (SIZE_T*)&n);
        VirtualProtectEx(hprocess, addr,
            bufsize, oldprotect, &oldprotect);
    }
    return ret;
}

WINHOOKDEF WINHOOK_EXPORT
INLINE BOOL winhook_patchmemorysex(HANDLE hprocess,
    LPVOID addrs[], void* bufs[],
    size_t bufsizes[], int n)
{
    int ret = 0;
    for (int i = 0; i < n; i++)
    {
        ret += winhook_patchmemoryex(hprocess,
            addrs[i], bufs[i], bufsizes[i]);
    }
    return ret;
}

INLINE int winhook_patchmemorypattern(const char *pattern)
{
    if (!pattern) return -1;
    size_t imagebase = (size_t)GetModuleHandleA(NULL);
    int res = 0;
    int flag_rel = 0;
    int j = 0;
    while (pattern[j]) j++;
    int patternlen = j;
    DWORD oldprotect;
    
    for(int i=0; i<patternlen; i++)
    {   
        if(pattern[i]=='#')
        {
            while(pattern[i]!='\n' && i<patternlen) i++;
            continue;
        }
        else if (pattern[i] == '\n' || pattern[i] == '\r')
        {
            continue;
        }
        else if (pattern[i]=='+')
        {
            flag_rel = 1;
            i++;
        }
        while (pattern[i]==' ') i++;

        size_t addr = 0;
        int flag_nextline = 0;
        for (;pattern[i]!=':' && i<patternlen; i++)
        {
            char c = pattern[i];
            if(c>='0' && c<='9') c -= '0';
            else if (c>='A' && c<='Z') c = c -'A' + 10;
            else if (c>='a' && c<='z') c = c -'a' - 10;
            else if (c=='\r' || c=='\n') {flag_nextline=1;break;}
            else if (c==' ') continue;
            else return -2;
            addr = (addr<<4) + c;
        }
        if(flag_nextline) continue;
        if(flag_rel) addr += imagebase;
        
        int n = 0;
        int v = 0;
        int start = i++;
        for(int j=0;j<2;j++)
        {
            n = 0;
            for(;pattern[i]!='\n' && i<patternlen;i++)
            {
                char c = pattern[i];
                if(c>='0' && c<='9') c -= '0';
                else if (c>='A' && c<='Z') c = c - 'A' + 10;
                else if (c>='a' && c<='z') c = c - 'a' + 10;
                else if (c==';') break;
                else continue;
                n++;
                if (j != 0)
                {
                    v = (v << 4) + c;
                    if (!(n & 1))
                    {
                        *(uint8_t*)(addr + (n>>1) -1) = v;
                        v = 0;
                        res++;
                    }
                }
            }
            if(n&1) return -3;
            if (j == 0) 
            {
                i = start;
                VirtualProtect((void*)addr, n>>1, PAGE_EXECUTE_READWRITE, &oldprotect);
            }
            else VirtualProtect((void*)addr, n>>1, oldprotect, &oldprotect);
        }
        flag_rel = 0;
    }
    return res;
}

INLINE int winhook_patchmemory1337ex(HANDLE hprocess, const char* pattern, size_t base, BOOL revert)
{
#define IS_ENDLINE(c) (c==';' || c=='\r' || c=='\n')
    enum FLAG1337 {
        RVA1337,
        OLDBYTE1337,
        NEWBYTE1337
    } flag1337 = RVA1337;

    if (hprocess == NULL) return -1;

    int res = 0;
    int i = 0;
    while (pattern[i]) i++;
    int patternlen = i;
    i = 0;
    while (pattern[i] != '>') i++; // title line
    while (!IS_ENDLINE(pattern[i])) i++;
    while (IS_ENDLINE(pattern[i])) i++;

    size_t rva = 0;
    uint8_t oldbyte = 0, newbyte = 0;
    for (; i < patternlen; i++)
    {
        char c = pattern[i];
        if (c == ':') // oldbyte indicator
        {
            flag1337 = OLDBYTE1337;
        }
        else if (c == '-') // newbyte indicator
        {
            if (pattern[i + 1] != '>') return -1;
            flag1337 = NEWBYTE1337;
            i++;
        }
        else if (IS_ENDLINE(c)) // flush patch
        {
            if (flag1337 == RVA1337) continue;
            uint8_t* patchbyte = revert ? &oldbyte : &newbyte;
            winhook_patchmemoryex(hprocess, (LPVOID)(base + rva), patchbyte, 1);
            flag1337 = RVA1337;
            rva = 0;
            oldbyte = 0;
            newbyte = 0;
            res++;
        }
        else if (c == ' ')
        {
            continue;
        }
        else
        {
            if (c >= '0' && c <= '9') c -= '0';
            else if (c >= 'A' && c <= 'Z') c = c - 'A' + 10;
            else if (c >= 'a' && c <= 'z') c = c - 'a' + 10;
            else continue;
            switch (flag1337)
            {
            case RVA1337:
                rva = (rva << 4)  | (uint8_t)c;
                break;
            case OLDBYTE1337:
                oldbyte = (oldbyte << 4) | (uint8_t)c;
                break;
            case NEWBYTE1337:
                newbyte = (newbyte << 4) | (uint8_t)c;
                break;
            }
        }
    }
    return res;
}

INLINE int winhook_patchmemoryipsex(HANDLE hprocess, const char* pattern, size_t base)
{
#define BYTE3_TO_UINT_BIGENDIAN(bp) \
     (((unsigned int)(bp)[0] << 16) & 0x00FF0000) | \
     (((unsigned int)(bp)[1] << 8) & 0x0000FF00) | \
     ((unsigned int)(bp)[2] & 0x000000FF)

#define BYTE2_TO_UINT_BIGENDIAN(bp) \
    (((unsigned int)(bp)[0] << 8) & 0xFF00) | \
    ((unsigned int) (bp)[1] & 0x00FF)

    if(strncmp(pattern, "PATCH", 5) !=0 ) return -1;
    int res = 0;
    const uint8_t* p = (uint8_t*)pattern + 5;
    while (strncmp((char*)p, "EOF", 3) != 0) 
    {
        unsigned int offset = BYTE3_TO_UINT_BIGENDIAN(p);
        unsigned int size = BYTE2_TO_UINT_BIGENDIAN(p + 3);
        p += 5;
        if (size == 0) // use RLE compress
        {
            unsigned int size_rle = BYTE2_TO_UINT_BIGENDIAN(p);
            return -2; //  not implemented yet
        }
        else
        {
            size_t addr = base + offset;
            winhook_patchmemoryex(hprocess, (LPVOID)addr, p, size);
            p += size;
            res += size;
        }
    }
    return res;
}

INLINE void* winhook_searchmemory(void* addr, size_t memsize,
    const char* pattern, size_t* pmatchsize)
{
    size_t i = 0;
    int matchend = 0;
    void* matchaddr = NULL;
    while (i < memsize)
    {
        int j = 0;
        int matchflag = 1;
        matchend = 0;
        while (pattern[j])
        {
            if (pattern[j] == 0x20)
            {
                j++;
                continue;
            }
            char _c1 = (((char*)addr)[i+matchend]>>4) & 0x0f;
            _c1 = _c1 < 10 ? _c1 + '0' : (_c1 - 10) + 'A';
            char _c2 = (((char*)addr)[i+matchend]&0xf) & 0x0f;
            _c2 = _c2 < 10 ? _c2 + '0' : (_c2 - 10) + 'A';
            if (pattern[j] != '?')
            {
                if (_c1 != pattern[j] && _c1 + 0x20 != pattern[j])
                {
                    matchflag = 0;
                    break;
                }
            }
            if (pattern[j + 1] != '?')
            {
                if (_c2 != pattern[j+1] && _c2 + 0x20 != pattern[j+1])
                {
                    matchflag = 0;
                    break;
                }
            }
            j += 2;
            matchend++;
        }
        if (matchflag)
        {
            matchaddr = (void*)((uint8_t*)addr + i);
            break;
        }
        i++;
    }
    if (pmatchsize) *pmatchsize = matchend;
    return matchaddr;
}

WINHOOKDEF WINHOOK_EXPORT
INLINE void* winhook_searchmemoryex(HANDLE hprocess,
    void* addr, size_t memsize,
    const char* pattern, size_t* pmatchsize)
{
    void* buf = VirtualAlloc(NULL, 
        memsize, MEM_COMMIT, PAGE_READWRITE);
    size_t bufsize = 0;
    ReadProcessMemory(hprocess, addr, 
        buf, memsize, (SIZE_T*)&bufsize);
    void* matchaddr = winhook_searchmemory(
        buf, memsize, pattern, pmatchsize);
    VirtualFree(buf, 0, MEM_RELEASE);
    if (!matchaddr) return matchaddr;
    size_t offset = (size_t)matchaddr - (size_t)buf;
    return (void*)((uint8_t*)addr + offset);
}

WINHOOKDEF WINHOOK_EXPORT 
INLINE BOOL winhook_iathookpe(LPCSTR targetDllName,
    void* mempe, PROC pfnOrg, PROC pfnNew)
{
    size_t imagebase = (size_t)mempe;
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)imagebase;
    PIMAGE_NT_HEADERS  pNtHeader = (PIMAGE_NT_HEADERS)
        ((uint8_t*)imagebase + pDosHeader->e_lfanew);
    PIMAGE_FILE_HEADER pFileHeader = &pNtHeader->FileHeader;
    PIMAGE_OPTIONAL_HEADER pOptHeader = &pNtHeader->OptionalHeader;
    PIMAGE_DATA_DIRECTORY pDataDirectory = pOptHeader->DataDirectory;
    PIMAGE_DATA_DIRECTORY pImpEntry =  
        &pDataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    PIMAGE_IMPORT_DESCRIPTOR pImpDescriptor =  
        (PIMAGE_IMPORT_DESCRIPTOR)(imagebase + pImpEntry->VirtualAddress);

    DWORD dwOldProtect = 0;
    for (; pImpDescriptor->Name; pImpDescriptor++) 
    {
        // find the dll IMPORT_DESCRIPTOR
        LPCSTR pDllName = (LPCSTR)(imagebase + pImpDescriptor->Name);
        if (!_stricmp(pDllName, targetDllName)) // ignore case
        {
            PIMAGE_THUNK_DATA pFirstThunk = (PIMAGE_THUNK_DATA)
                (imagebase + pImpDescriptor->FirstThunk);
            // find the iat function va
            for (; pFirstThunk->u1.Function; pFirstThunk++) 
            {
                if (pFirstThunk->u1.Function == (size_t)pfnOrg)
                {
                    VirtualProtect((LPVOID)&pFirstThunk->u1.Function,
                        4, PAGE_EXECUTE_READWRITE, &dwOldProtect);
                    pFirstThunk->u1.Function = (size_t)pfnNew;
                    VirtualProtect((LPVOID)&pFirstThunk->u1.Function,
                        4, dwOldProtect, &dwOldProtect);
                    return TRUE;
                }
            }
        }
    }
    return FALSE;
}

#ifndef WINHOOK_NOINLINEHOOK
#ifdef WINHOOK_USEDETOURS
#error "detours are not included in this program"
#include "detours.h"
WINHOOKDEF WINHOOK_EXPORT 
int winhook_inlinehooks(PVOID pfnTargets[],
    PVOID pfnNews[], PVOID pfnOlds[], size_t n)
{
    int i=0;
    DetourRestoreAfterWith();
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    for(int i=0; i<n ;i++)
    {
        if(!pfnNews[i] || !pfnTargets[i]) continue;
        pfnOlds[i] = pfnTargets[i];
        DetourAttach(&pfnOlds[i], pfnNews[i]);
    }
    DetourTransactionCommit();
    return i;
}

WINHOOKDEF WINHOOK_EXPORT
int winhook_inlineunhooks(PVOID pfnTargets[],
    PVOID pfnNews[], PVOID pfnOlds[], size_t n)
{
    int i = 0;
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    for(i=0; i<n ;i++)
    {
        if(!pfnNews[i] || !pfnTargets[i]) continue;
        DetourDetach(&pfnOlds[i], pfnNews[i]);
    }
    DetourTransactionCommit();
    return i;
}
#else // use minhook
#define MINHOOK_IMPLEMENTATION
#ifdef USE_COMPAT
#include "stb_minhook_v1330.h"
#else
#include "stb_minhook.h"
#endif
WINHOOKDEF WINHOOK_EXPORT 
int winhook_inlinehooks(PVOID pfnTargets[],
    PVOID pfnNews[], PVOID pfnOlds[], size_t n)
{
    int i;
    MH_Initialize();
    for(i=0; i<n ;i++)
    {
        MH_STATUS status;
        if(!pfnNews[i] || !pfnTargets[i]) continue;
        status = MH_CreateHook(pfnTargets[i], pfnNews[i], &pfnOlds[i]);
        if(status!= MH_OK) return i;
        status = MH_EnableHook(pfnTargets[i]);
        if(status!= MH_OK) return i;
    }
    return i;
}

WINHOOKDEF WINHOOK_EXPORT
int winhook_inlineunhooks(PVOID pfnTargets[],
    PVOID pfnNews[], PVOID pfnOlds[], size_t n)
{
    int i;
    for(i=0; i<n ;i++)
    {
        if(!pfnNews[i] || !pfnTargets[i]) continue;
        MH_DisableHook(pfnTargets[i]);
    }
    if(MH_Uninitialize() != MH_OK) return 0;
    return i;
}
#endif
#endif

#endif

/**
 * history:
 * v0.1 initial version
 * v0.2 add make this to single file
 * v0.2.2 add WINHOOK_STATIC, WINHOOK_SHARED macro
 * v0.2.3 change name to winhook.h and add guard for function name
 * v0.2.4 add winhook_searchmemory
 * v0.2.5 add minhook backend, compatible withh gcc, tcc
 * v0.2.6 support function to patch or search other process memory
 * v0.2.7 add win_startexeinject, fix winhook_searchmemoryex match bug
 * v0.3 use javadoc style, add winhook_patchmemorypattern
 * v0.3.1 add winhook_patchmemory1337, winhook_patchmemoryips
*/