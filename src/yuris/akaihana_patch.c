/*	
    for KoezaruWaAkaihana chs support
	v0.1, developed by devseed
*/
#include<windows.h>
#include<stdio.h>

__declspec(dllexport) void dummy()
{

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

BOOL iat_hook(LPCSTR targetDllName, PROC pfnOrg, PROC pfnNew)
{
    return iat_hook_module(targetDllName, NULL, pfnOrg, pfnNew);
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

HWND WINAPI CreateWindowExA_hook(
   DWORD dwExStyle, LPCSTR lpClassName, LPCSTR lpWindowName,
   DWORD dwStyle, int X, int Y, int nWidth, int nHeight, 
   HWND hWndParent, HMENU hMenu, HINSTANCE hInstance, LPVOID lpParam
)
{
    // char title[] = {'a', 'd', 'd', 0, 0};
    // memcpy(lpWindowName, title, sizeof(title));
    // MessageBoxA(0, lpWindowName, "title", 0);
    return CreateWindowExA(dwExStyle, lpClassName, lpWindowName,    
        dwStyle, X, Y, nWidth, nHeight, 
        hWndParent, hMenu, hInstance, lpParam);
}

HFONT WINAPI CreateFontIndirectA_hook(LOGFONTA *lplf)
{
    lplf->lfCharSet = GB2312_CHARSET;
    strcpy(lplf->lfFaceName, "simhei");
    return CreateFontIndirectA(lplf);
}

void install_hooks()
{
#ifdef _DEBUG
    AllocConsole();
    //MessageBoxA(0, "debug install", "debug", 0);
    freopen("CONOUT$", "w", stdout);
    printf("install hook\n");
#endif
    if(!iat_hook("User32.dll", (PROC)CreateWindowExA, 
        (PROC)CreateWindowExA_hook)) // not used, because multi window
    {
        MessageBoxA(0, "CreateWindowExA hook error", "IAThook error", 0);
    }

    if(!iat_hook("Gdi32.dll", (PROC)CreateFontIndirectA, 
        (PROC)CreateFontIndirectA_hook))
    {
        MessageBoxA(0, "CreateFontIndirectA hook error", "IAThook error", 0);
    }
	
	// hook asci table
    static char gbkAsciTable[]= 
    {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x00,
    };
	LPVOID asciTableAddr = (LPVOID)0x4ac0a0;
    if(!patch_memory(asciTableAddr, gbkAsciTable, sizeof(gbkAsciTable)))
	{
		MessageBoxA(0, "patch_memory error", "IAThook error", 0);
	}
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        install_hooks();
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}