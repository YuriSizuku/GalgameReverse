/* 
    a tool to attach a dll inside a pe file
    v0.1, developed by devseed
*/

#include <stdio.h>
#include "winpe.h"

// these functions are stub function, will be filled by python
unsigned char g_oepshellcode[] = {0x90};
unsigned char g_memiatshellcode[] = {0x90};

void _oepshellcode(void *mempe_exe, void *mempe_dll, 
    void *shellcode, PIMAGE_SECTION_HEADER psecth, DWORD orgoeprva)
{
    // PE struct declear
    void *mempe;
    PIMAGE_DOS_HEADER pDosHeader;
    PIMAGE_NT_HEADERS  pNtHeader;
    PIMAGE_FILE_HEADER pFileHeader;
    PIMAGE_OPTIONAL_HEADER pOptHeader;
    PIMAGE_DATA_DIRECTORY pDataDirectory;
    PIMAGE_DATA_DIRECTORY pImpEntry;
    PIMAGE_IMPORT_DESCRIPTOR pImpDescriptor;
    PIMAGE_THUNK_DATA pFtThunk = NULL;
    PIMAGE_THUNK_DATA pOftThunk = NULL;
    LPCSTR pDllName = NULL;
    PIMAGE_IMPORT_BY_NAME pFuncName = NULL;

    // bind the pointer to buffer
    size_t end = sizeof(g_oepshellcode);
    size_t *pexeoepva = (size_t*)(g_oepshellcode + end - 6*sizeof(size_t));
    size_t *pdllbase = (size_t*)(g_oepshellcode + end - 5*sizeof(size_t));
    size_t *pdlloepva = (size_t*)(g_oepshellcode + end - 4*sizeof(size_t));
    size_t *pmemiatbind = (size_t*)(g_oepshellcode + end - 3*sizeof(size_t));
    size_t *pexeloadlibrarya = (size_t*)(g_oepshellcode + end - 2*sizeof(size_t));
    size_t *pexegetprocessaddress = (size_t*)(g_oepshellcode + end - 1*sizeof(size_t));

    // get the information of exe
    mempe = mempe_exe;
    pDosHeader = (PIMAGE_DOS_HEADER)mempe;
    pNtHeader = (PIMAGE_NT_HEADERS)((void*)mempe + pDosHeader->e_lfanew);
    pFileHeader = &pNtHeader->FileHeader;
    pOptHeader = &pNtHeader->OptionalHeader;
    pDataDirectory = pOptHeader->DataDirectory;
    pImpEntry =  &pDataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    pImpDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(mempe + pImpEntry->VirtualAddress);
    size_t exeimagebase = pOptHeader->ImageBase;
    DWORD exeoeprva = pOptHeader->AddressOfEntryPoint;
    DWORD exeloadlibrarya_rva = winpe_memfindiat(
        mempe, "kernel32.dll", "LoadLibraryA");
    DWORD exegetprocessaddress_rva = winpe_memfindiat(
        mempe, "kernel32.dll", "GetProcAddress");
    
    // get the information of dll
    mempe = mempe_dll;
    pDosHeader = (PIMAGE_DOS_HEADER)mempe;
    pNtHeader = (PIMAGE_NT_HEADERS)((void*)mempe + pDosHeader->e_lfanew);
    pFileHeader = &pNtHeader->FileHeader;
    pOptHeader = &pNtHeader->OptionalHeader;
    pDataDirectory = pOptHeader->DataDirectory;
    size_t dllimagebase = pOptHeader->ImageBase;
    DWORD dlloeprva = pOptHeader->AddressOfEntryPoint;

    // fill the address table
    *pexeoepva = exeimagebase + orgoeprva;
    *pdllbase =  dllimagebase;
    *pdlloepva = dllimagebase + dlloeprva;
    *pmemiatbind = exeimagebase + psecth->VirtualAddress + end;
    *pexeloadlibrarya = exeimagebase + exeloadlibrarya_rva;
    *pexegetprocessaddress = exeimagebase + exegetprocessaddress_rva;

    // copy to the target
    memcpy(shellcode, g_oepshellcode, sizeof(g_oepshellcode));
    memcpy(shellcode + end, g_memiatshellcode, sizeof(g_memiatshellcode));
}

int injectdll_mem(const char *exepath, 
    const char *dllpath, const char *outpath)
{
    size_t exe_overlayoffset = 0;
    size_t exe_overlaysize = 0;
    void *mempe_dll = NULL;
    size_t mempe_dllsize = 0;
    void *mempe_exe = NULL;
    size_t mempe_exesize = 0;
    void *overlay_exe = NULL;
    size_t overlay_exesize = 0;
    size_t imgbase_exe = 0;
    IMAGE_SECTION_HEADER secth = {0};
    #define SHELLCODE_SIZE 0X1000
    char shellcode[SHELLCODE_SIZE];

    // load exe and dll pe 
    mempe_exe = winpe_memload_file(exepath, &mempe_exesize, TRUE);
    mempe_dll = winpe_memload_file(dllpath, &mempe_dllsize, TRUE);
    overlay_exe = winpe_overlayload_file(exepath, &overlay_exesize);
    void *mempe = mempe_exe;
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)mempe;
    PIMAGE_NT_HEADERS  pNtHeader = (PIMAGE_NT_HEADERS)
        ((void*)mempe + pDosHeader->e_lfanew);
    PIMAGE_FILE_HEADER pFileHeader = &pNtHeader->FileHeader;
    PIMAGE_OPTIONAL_HEADER pOptHeader = &pNtHeader->OptionalHeader;
    imgbase_exe = pOptHeader->ImageBase;

    // append the dll section and adjust
    secth.Characteristics = IMAGE_SCN_MEM_READ | 
        IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE;
    secth.Misc.VirtualSize = mempe_dllsize + SHELLCODE_SIZE;
    secth.SizeOfRawData = mempe_dllsize + SHELLCODE_SIZE;
    strcpy(secth.Name, ".module");
    winpe_noaslr(mempe_exe);
    winpe_appendsecth(mempe_exe, &secth);
    DWORD orgoeprva = winpe_setoep(mempe_exe, secth.VirtualAddress);
    winpe_memreloc(mempe_dll, imgbase_exe + secth.VirtualAddress + SHELLCODE_SIZE);
    _oepshellcode(mempe_exe, mempe_dll, shellcode, &secth, orgoeprva);

    // write data to new exe
    FILE *fp = fopen(outpath, "wb");
    fwrite(mempe_exe, 1, mempe_exesize, fp);
    fwrite(shellcode, 1, SHELLCODE_SIZE, fp);
    fwrite(mempe_dll, 1, mempe_dllsize, fp);
    if(overlay_exe) fwrite(overlay_exe, 1, overlay_exesize, fp);
    fclose(fp);
   
    if(overlay_exe) free(overlay_exe);
    if(mempe_exe) free(mempe_exe);
    if(mempe_dll) free(mempe_dll);
    return 0;
}

int main(int argc, char *argv[])
{
    char outpath[MAX_PATH];
    if(argc < 3)
    {
        printf("usage: win_injectmemdll exepath dllpath [outpath]\n");
        printf("v0.1, developed by devseed\n");
        return 0;
    }

    if(argc >= 4) strcpy(outpath, argv[3]);
    else strcpy(outpath, "out.exe");
    return injectdll_mem(argv[1], argv[2], outpath);
}