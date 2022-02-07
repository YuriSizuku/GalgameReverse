/*
  win_hook.h, by devseed, v0.2.2
  windows dyamic hook util functions wrappers 

  history:
    v0.1 initial version
    v0.2 add make this to single file
    v0.2.2 add WIN_HOOK_STATIC, WIN_HOOK_SHARED macro
*/

#ifndef _WIN_HOOK_H
#define _WIN_HOOK_H
#include <Windows.h>

#ifndef WINHOOKDEF
#ifdef WIN_HOOK_STATIC
#define WINHOOKDEF static
#else
#define WINHOOKDEF extern
#endif
#endif

#ifndef WIN_HOOK_SHARED
#define WIN_HOOK_EXPORT
#else
#ifdef _WIN32
#define WIN_HOOK_EXPORT __declspec(dllexport)
#else
#define WIN_HOOK_EXPORT __attribute__((visibility("default")))
#endif
#endif

#ifdef __cplusplus
extern "C" {
#endif
// PE functions
WINHOOKDEF WIN_HOOK_EXPORT 
size_t get_overlay_offset(BYTE *pe);

// loader functions
/* 
    start a exe by CreateProcess
*/
WINHOOKDEF WIN_HOOK_EXPORT 
HANDLE start_exe(LPCSTR exepath, LPSTR cmdstr);

/*
    get the process handle by exename
*/
WINHOOKDEF WIN_HOOK_EXPORT 
HANDLE GetProcessByName(LPCWSTR exename); 

/*
    dynamic inject a dll into a process
 */ 
WINHOOKDEF WIN_HOOK_EXPORT 
BOOL inject_dll(HANDLE hProcess, LPCSTR dllname); 

/*
    alloc a console for the program
*/
WINHOOKDEF WIN_HOOK_EXPORT 
void install_console();


// dynamic hook functions
WINHOOKDEF WIN_HOOK_EXPORT 
BOOL patch_memory(LPVOID addr, void* buf, 
    size_t bufsize);

/* 
    iat_hook_module is for windows dll, 
    moduleDllName is which dll to hook iat
*/
WINHOOKDEF WIN_HOOK_EXPORT 
BOOL iat_hook_module(LPCSTR targetDllName, 
    LPCSTR moduleDllName, PROC pfnOrg, PROC pfnNew);

/*
    iat dynamiclly hook, 
    replace the pfgNew with pfnOrg function 
    in targetDllName, 
    iat_hook is for windows EXE, 
    targetDllName is like "user32.dll", "kernel32.dll"
*/
WINHOOKDEF WIN_HOOK_EXPORT 
BOOL iat_hook(LPCSTR targetDllName, 
    PROC pfnOrg, PROC pfgNew);

/*
    using detour for inline hook, 
    passing the array with NULL end as params, 
    for example, use pfnOlds[n] for old function invoke

    void(*g_pfnAbout)() = NULL;
    ULONGLONG rva = 0x11D40;
    HMODULE hMod = GetModuleHandleA(NULL);
    PVOID pfnOlds[2] = { (PVOID)((ULONGLONG)hMod + rva), NULL }, pfnNews[2] = { test_hook, NULL };
    inline_hooks(pfnOlds, pfnNews);
    g_pfnAbout = (void(*)())(pfnOlds[0]);
*/
WINHOOKDEF WIN_HOOK_EXPORT
int inline_hooks(PVOID pfnOlds[], PVOID pfnNews[]); 

WINHOOKDEF WIN_HOOK_EXPORT
int inline_unhooks(PVOID pfnOlds[], PVOID pfnNews[]);
#endif 

#ifdef __cplusplus
}
#endif

#ifdef WIN_HOOK_IMPLEMENTATION
/*
  win_hook.c, by devseed, v0.2.1
  windows dyamic hook util functions wrappers 
*/

#include <Windows.h>
#include <tlhelp32.h>
#include <stdio.h>
// PE functions
WINHOOKDEF WIN_HOOK_EXPORT 
size_t get_overlay_offset(BYTE *pe)
{
#ifdef _WIN64
#define ADDR_TYPE DWORD
#else
#define ADDR_TYPE ULONGLONG
#endif    
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pe;
    
    PIMAGE_NT_HEADERS  pNtHeader = (PIMAGE_NT_HEADERS)
        ((ADDR_TYPE)pe + pDosHeader->e_lfanew);
    PIMAGE_FILE_HEADER pFileHeader = &pNtHeader->FileHeader;
    PIMAGE_OPTIONAL_HEADER pOptHeader = &pNtHeader->OptionalHeader;
    PIMAGE_DATA_DIRECTORY pDataDirectory = pOptHeader->DataDirectory;
 
    PIMAGE_SECTION_HEADER pSectHeader = (PIMAGE_SECTION_HEADER)
        ((ADDR_TYPE)pOptHeader + pFileHeader->SizeOfOptionalHeader);
    WORD sectNum = pFileHeader->NumberOfSections;

    return pSectHeader[sectNum-1].PointerToRawData + 
           pSectHeader[sectNum-1].SizeOfRawData;
}

// loader functions
WINHOOKDEF WIN_HOOK_EXPORT 
HANDLE start_exe(LPCSTR exepath, LPSTR cmdstr)
{
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&pi, sizeof(pi));
    ZeroMemory(&si, sizeof(si));
    if (!CreateProcessA(exepath, cmdstr, 
        NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi))
        return NULL;
    return pi.hProcess;
}

WINHOOKDEF WIN_HOOK_EXPORT 
HANDLE GetProcessByName(LPCWSTR exename)
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
            if (wcscmp((const wchar_t*)process.szExeFile, exename) == 0)
            {
                pid = process.th32ProcessID;
                break;
            }
        } while (Process32Next(snapshot, &process));
    }
    CloseHandle(snapshot);
    if (pid != 0) return OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    return NULL;     // Not found
}

WINHOOKDEF WIN_HOOK_EXPORT
BOOL inject_dll(HANDLE hProcess, LPCSTR dllname)
{
    LPVOID param_addr = VirtualAllocEx(hProcess, 0, 0x100, MEM_COMMIT, PAGE_READWRITE);
    SIZE_T count;
    if (param_addr == NULL) return FALSE;
    WriteProcessMemory(hProcess, param_addr, dllname, strlen(dllname)+1, &count);

    HMODULE kernel = GetModuleHandleA("Kernel32");
    FARPROC pfnLoadlibraryA = GetProcAddress(kernel, "LoadLibraryA");
    HANDLE threadHandle = CreateRemoteThread(hProcess, NULL, 0, 
        (LPTHREAD_START_ROUTINE)pfnLoadlibraryA, param_addr, 0, NULL); 
   
    if (threadHandle == NULL) return FALSE;
    WaitForSingleObject(threadHandle, -1);
    VirtualFreeEx(hProcess, param_addr, 0x100, MEM_COMMIT);

    return TRUE;
}

WINHOOKDEF WIN_HOOK_EXPORT 
void install_console()
{
    AllocConsole();
    freopen("CONOUT$", "w", stdout);    
}

// dynamic hook functions
WINHOOKDEF WIN_HOOK_EXPORT 
BOOL patch_memory(LPVOID addr, void* buf, size_t bufsize)
{
	DWORD oldprotect;
    BOOL ret = VirtualProtect(addr, bufsize, PAGE_EXECUTE_READWRITE, &oldprotect);
	if(ret)
	{
		CopyMemory(addr, buf, bufsize);
        VirtualProtect(addr, bufsize, oldprotect, &oldprotect);
	}
    return ret;
}

WINHOOKDEF WIN_HOOK_EXPORT 
BOOL iat_hook_module(LPCSTR targetDllName, 
    LPCSTR moduleDllName, PROC pfnOrg, PROC pfnNew)
{
#ifdef _WIN64
#define VA_TYPE ULONGLONG
#else
#define VA_TYPE DWORD
#endif
    DWORD dwOldProtect = 0;
    VA_TYPE imageBase = (VA_TYPE)GetModuleHandleA(moduleDllName);
    LPBYTE pNtHeader = (LPBYTE)(*(DWORD *)((LPBYTE)imageBase + 0x3c) + imageBase); 
#ifdef _WIN64
    VA_TYPE impDescriptorRva = *((DWORD*)&pNtHeader[0x90]);
#else
    VA_TYPE impDescriptorRva = *((DWORD*)&pNtHeader[0x80]); 
#endif
    PIMAGE_IMPORT_DESCRIPTOR pImpDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(imageBase + impDescriptorRva); 
    for (; pImpDescriptor->Name; pImpDescriptor++) // find the dll IMPORT_DESCRIPTOR
    {
        LPCSTR pDllName = (LPCSTR)(imageBase + pImpDescriptor->Name);
        if (!_stricmp(pDllName, targetDllName)) // ignore case
        {
            PIMAGE_THUNK_DATA pFirstThunk = (PIMAGE_THUNK_DATA)(imageBase + pImpDescriptor->FirstThunk);
            for (; pFirstThunk->u1.Function; pFirstThunk++) // find the iat function va
            {
                if (pFirstThunk->u1.Function == (VA_TYPE)pfnOrg)
                {
                    VirtualProtect((LPVOID)&pFirstThunk->u1.Function, 4, PAGE_EXECUTE_READWRITE, &dwOldProtect);
                    pFirstThunk->u1.Function = (VA_TYPE)pfnNew;
                    VirtualProtect((LPVOID)&pFirstThunk->u1.Function, 4, dwOldProtect, &dwOldProtect);
                    return TRUE;
                }
            }
        }
    }
    return FALSE;
}

WINHOOKDEF WIN_HOOK_EXPORT 
BOOL iat_hook(LPCSTR targetDllName, PROC pfnOrg, PROC pfnNew)
{
    return iat_hook_module(targetDllName, NULL, pfnOrg, pfnNew);
}

#ifdef WIN_HOOK_DETOURS
#include "detours.h"
WINHOOKDEF WIN_HOOK_EXPORT 
int inline_hooks(PVOID pfnOlds[], PVOID pfnNews[])
{
    int i=0;
    DetourRestoreAfterWith();
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    for(i=0; pfnNews[i]!=NULL ;i++)
        DetourAttach(&pfnOlds[i], pfnNews[i]);
    DetourTransactionCommit();
    return i;
}

WINHOOKDEF WIN_HOOK_EXPORT
int inline_unhooks(PVOID pfnOlds[], PVOID pfnNews[])
{
    int i = 0;
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    for (i = 0; pfnNews[i] != NULL; i++)
        DetourDetach(&pfnOlds[i], pfnNews[i]);
    DetourTransactionCommit();
    return i;
}
#endif
#endif