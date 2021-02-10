#include "hook_util.h"
#include "tlhelp32.h"
#define _DETOURS
#ifdef _DETOURS
#include "detours.h"
#ifdef _WIN64
#pragma comment(lib,"detours_x64.lib")
#else
#pragma comment(lib,"detours.lib")
#endif
int inline_hooks(PVOID *pfnOlds, PVOID *pfnNews)
{
    int i=0;
    DetourRestoreAfterWith();
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    for(i=0;*(pfnOlds+i)!=NULL;i++)
        DetourAttach(pfnOlds + i, *(pfnNews + i));
    DetourTransactionCommit();
    return i;
}

int inline_unhooks(PVOID* pfnOlds, PVOID* pfnNews)
{
    int i = 0;
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    for (i = 0; *(pfnOlds + i) != NULL; i++)
        DetourDetach(pfnOlds + i, *(pfnNews + i));
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
            if (wcscmp(process.szExeFile, exename) == 0)
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
    if (!CreateProcessA(exepath, cmdstr, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi))
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
    FARPROC funcLoadlibraryA = GetProcAddress(kernel, "LoadLibraryA");
    HANDLE threadHandle = CreateRemoteThread(hProcess, NULL, NULL, (LPTHREAD_START_ROUTINE)funcLoadlibraryA, param_addr, NULL, NULL); //DLL_THREAD_ATTACH
   
    if (threadHandle == NULL) return FALSE;
    WaitForSingleObject(threadHandle, -1);
    VirtualFreeEx(hProcess, param_addr, 0x100, MEM_COMMIT);

    return TRUE;
}

BOOL iat_hook(LPCSTR szDllName, PROC pfnOrg, PROC pfnNew)
{
    HMODULE hMod;
    LPCSTR szLibName;
    PIMAGE_IMPORT_DESCRIPTOR pImportDesc;
    PIMAGE_THUNK_DATA pThunk;
    DWORD dwOldProtect;
#ifdef _WIN64
#define POINTER_TYPE ULONGLONG
#else
#define POINTER_TYPE DWORD
#endif
    POINTER_TYPE dwRVA;
    PBYTE pAddr;
    hMod = GetModuleHandle(NULL);
    pAddr = (PBYTE)hMod;
    pAddr += *((DWORD*)&pAddr[0x3C]); // pAddr = VA to PE signature (IMAGE_NT_HEADERS)
#ifdef _WIN64
    dwRVA = *((DWORD*)&pAddr[0x90]); // dwRVA = RVA to IMAGE_IMPORT_DESCRIPTOR Table
#else
    dwRVA = *((DWORD*)&pAddr[0x80]); // dwRVA = RVA to IMAGE_IMPORT_DESCRIPTOR Table
#endif
    pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)((POINTER_TYPE)hMod + dwRVA); //pImportDesc = VA to IMAGE_IMPORT_DESCRIPTOR Table
    for (; pImportDesc->Name; pImportDesc++) // IMAGE_IMPORT_DESCRIPTOR[] 以空的IMAGE_IMPORT_DESCRIPTOR为结尾
    {
        szLibName = (LPCSTR)((POINTER_TYPE)hMod + pImportDesc->Name);
        if (!_stricmp(szLibName, szDllName))
        {
            pThunk = (PIMAGE_THUNK_DATA)((POINTER_TYPE)hMod + pImportDesc->FirstThunk);
            for (; pThunk->u1.Function; pThunk++)
            {
                if (pThunk->u1.Function == (POINTER_TYPE)pfnOrg)
                {
                    VirtualProtect((LPVOID)&pThunk->u1.Function, 4, PAGE_EXECUTE_READWRITE, &dwOldProtect);
                    pThunk->u1.Function = (POINTER_TYPE)pfnNew;
                    VirtualProtect((LPVOID)&pThunk->u1.Function, 4, dwOldProtect, &dwOldProtect);
                    return TRUE;
                }
            }
        }
    }
    return FALSE;
}