#ifndef _ATTACH_HOOK_H
#define _ATTACH_HOOK_H
#endif 
#include<Windows.h>
HANDLE GetProcessByName(LPCWSTR exename);
BOOL inject_dll(HANDLE hProcess, LPCSTR dllname);
BOOL iat_hook(LPCSTR szDllName, PROC pfnOrg, PROC pfgNew);
int inline_hooks(PVOID* pfnOlds, PVOID* pfnNews);
int inline_unhooks(PVOID* pfnOlds, PVOID* pfnNews);