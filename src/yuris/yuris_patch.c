/*	
    for universe yuris chs support
	v0.1, developed by devseed
*/
#include<stdint.h>
#include<stdio.h>
#include<string.h>
#include<windows.h>
#ifdef USE_WINDVFS
#define WINDVFS_IMPLEMENTATION
#include "windvfs.h"
#endif

__declspec(dllexport) void dummy()
{

}

// util functions
void* search_memory(void* addr,
    size_t n, const char* pattern, size_t* pmatchsize)
{
    int i = 0;
    int matchend = 0;
    void* matchaddr = NULL;
    while (i < n)
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
            char _c1 = (((char*)addr)[i+matchend]>>4);
            _c1 = _c1 < 10 ? _c1 + 0x30 : _c1 + 0x41;
            char _c2 = (((char*)addr)[i+matchend]&0xf);
            _c2 = _c2 < 10 ? _c2 + 0x30 : _c2 + 0x41;
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

size_t get_imagesize(void *pe)
{
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pe;
    PIMAGE_NT_HEADERS  pNtHeader = (PIMAGE_NT_HEADERS)
        ((uint8_t*)pe + pDosHeader->e_lfanew);
    PIMAGE_FILE_HEADER pFileHeader = &pNtHeader->FileHeader;
    PIMAGE_OPTIONAL_HEADER pOptHeader = &pNtHeader->OptionalHeader;
    size_t imagesize = pOptHeader->SizeOfImage;
    return imagesize; 
}

BOOL iat_hook_module(LPCSTR targetDllName, 
    LPCSTR moduleDllName, PROC pfnOrg, PROC pfnNew)
{
    size_t imageBase = (size_t)GetModuleHandleA(moduleDllName);
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)imageBase;
    PIMAGE_NT_HEADERS  pNtHeader = (PIMAGE_NT_HEADERS)
        ((uint8_t*)imageBase + pDosHeader->e_lfanew);
    PIMAGE_FILE_HEADER pFileHeader = &pNtHeader->FileHeader;
    PIMAGE_OPTIONAL_HEADER pOptHeader = &pNtHeader->OptionalHeader;
    PIMAGE_DATA_DIRECTORY pDataDirectory = pOptHeader->DataDirectory;
    PIMAGE_DATA_DIRECTORY pImpEntry =  
        &pDataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    PIMAGE_IMPORT_DESCRIPTOR pImpDescriptor =  
        (PIMAGE_IMPORT_DESCRIPTOR)(imageBase + pImpEntry->VirtualAddress);

    DWORD dwOldProtect = 0;
    for (; pImpDescriptor->Name; pImpDescriptor++) 
    {
        // find the dll IMPORT_DESCRIPTOR
        LPCSTR pDllName = (LPCSTR)(imageBase + pImpDescriptor->Name);
        if (!_stricmp(pDllName, targetDllName)) // ignore case
        {
            PIMAGE_THUNK_DATA pFirstThunk = (PIMAGE_THUNK_DATA)
                (imageBase + pImpDescriptor->FirstThunk);
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

BOOL iat_hook(LPCSTR targetDllName, PROC pfnOrg, PROC pfnNew)
{
    return iat_hook_module(targetDllName, NULL, pfnOrg, pfnNew);
}

// yuris hook functions
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

void install_fonthook()
{
    if(!iat_hook("USER32.dll", 
        GetProcAddress(GetModuleHandleA("USER32.dll"), "CreateWindowExA"), 
        (PROC)CreateWindowExA_hook)) // not used, because multi window
    {
        MessageBoxA(0, "CreateWindowExA hook error", "IAThook error", 0);
    }

    if(!iat_hook("GDI32.dll",
        GetProcAddress(GetModuleHandleA("GDI32.dll"), "CreateFontIndirectA"), 
        (PROC)CreateFontIndirectA_hook))
    {
        MessageBoxA(0, "CreateFontIndirectA hook error", "IAThook error", 0);
    }
}

void install_sjistablehook()
{
    const char* sjisAsciTablePattern = "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 00 00 00";
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

    LPVOID baseaddr = (LPVOID)GetModuleHandleA(NULL);
    size_t memsize = get_imagesize(baseaddr);
    printf("baseaddr=%p, memsize=%x\n", baseaddr, memsize);
	LPVOID asciTableAddr =  search_memory(baseaddr, memsize, 
        sjisAsciTablePattern, NULL);// (LPVOID)0x58F0A0;
    printf("find sjistable at %p\n", asciTableAddr);
    if(!patch_memory(asciTableAddr, gbkAsciTable, sizeof(gbkAsciTable)))
	{
		MessageBoxA(0, "patch_memory error", "IAThook error", 0);
	}
}

void install_hooks()
{
#ifdef _DEBUG
    AllocConsole();
    //MessageBoxA(0, "debug install", "debug", 0);
    freopen("CONOUT$", "w", stdout);
    printf("install yuris_patch, v0.2, build 220504\n");
#endif
    install_fonthook();
    install_sjistablehook();
#ifdef USE_WINDVFS
    windvfs_install();
#endif
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

/*
history:
v0.1 initial version, add search memory for sjis table
v0.2 compatible with gcc, tcc
*/