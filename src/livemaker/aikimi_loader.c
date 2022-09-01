#include <stdio.h>
#include <windows.h>
#include "detours.h"

#ifndef _DEBUG
#pragma comment(linker, "/subsystem:windows /entry:mainCRTStartup")
#endif

int main(int argc, char* argv[])
{
    //test();
    STARTUPINFOA si = {0};
    PROCESS_INFORMATION pi = {0};
    si.cb = sizeof(STARTUPINFOA);
    ZeroMemory(&pi, sizeof(pi));
    ZeroMemory(&si, sizeof(si));
    
    // CreateProcessA(
    //     "aikimi.exe", NULL, NULL, NULL, 
    //     FALSE, 0, NULL, NULL, &si, &pi);

    if(!DetourCreateProcessWithDllA(
        "aikimi.exe", NULL, NULL, NULL, 
        FALSE, 0, NULL, NULL, &si, &pi, 
        "aikimi_patch.dll", NULL))
    {
        MessageBoxA(NULL, "start aikimi.exe failed!", "start error", 0);
        return -1;
    }
    WaitForSingleObject(pi.hProcess, INFINITE);
	CloseHandle(pi.hThread);
	CloseHandle(pi.hProcess);
    return 0;
}