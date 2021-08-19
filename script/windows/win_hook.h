/*
  win_hook.h, by devseed, v0.2
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