/*
  win_hook.h, by devseed, v0.2.1
  windows dyamic hook util functions wrappers 
*/

#ifndef _WIN_HOOK_H
#define _WIN_HOOK_H
#include <Windows.h>
//get the process handle by exename
HANDLE GetProcessByName(LPCWSTR exename); 

// dynamic inject a dll into a process
BOOL inject_dll(HANDLE hProcess, LPCSTR dllname); 

// start a exe by CreateProcess
HANDLE start_exe(LPCSTR exepath, LPSTR cmdstr);

// alloc a console for the program
void install_console();

// iat dynamiclly hook, replace the pfgNew with pfnOrg function in targetDllName, 
// iat_hook is for windows EXE, targetDllName is like "user32.dll", "kernel32.dll"
BOOL iat_hook(LPCSTR targetDllName, PROC pfnOrg, PROC pfgNew);
// iat_hook_module is for windows dll, moduleDllName is which dll to hook iat
BOOL iat_hook_module(LPCSTR targetDllName, LPCSTR moduleDllName, PROC pfnOrg, PROC pfnNew);

BOOL patch_memory(LPVOID addr, void* buf, size_t bufsize);

// using detour for inline hook, 
// passing the array with NULL end as params, for example, use pfnOlds[n] for old function invoke
//
// void(*g_pfnAbout)() = NULL;
// ULONGLONG rva = 0x11D40;
// HMODULE hMod = GetModuleHandleA(NULL);
// PVOID pfnOlds[2] = { (PVOID)((ULONGLONG)hMod + rva), NULL }, pfnNews[2] = { test_hook, NULL };
// inline_hooks(pfnOlds, pfnNews);
// g_pfnAbout = (void(*)())(pfnOlds[0]); // use old function
int inline_hooks(PVOID pfnOlds[], PVOID pfnNews[]); 
int inline_unhooks(PVOID pfnOlds[], PVOID pfnNews[]);
#endif 

#ifdef WIN_HOOK_IMPLEMENTATION
/*
  win_hook.c, by devseed, v0.2.1
  windows dyamic hook util functions wrappers 
*/

#include <Windows.h>
#include <tlhelp32.h>
#include <stdio.h>

#ifdef USE_DETOURS
#include "detours.h"
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

void install_console()
{
    AllocConsole();
    freopen("CONOUT$", "w", stdout);    
}

BOOL iat_hook(LPCSTR targetDllName, PROC pfnOrg, PROC pfnNew)
{
    return iat_hook_module(targetDllName, NULL, pfnOrg, pfnNew);
}

BOOL iat_hook_module(LPCSTR targetDllName, LPCSTR moduleDllName, PROC pfnOrg, PROC pfnNew)
{;
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
#endif