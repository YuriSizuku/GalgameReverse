/*
  winpe.h, by devseed, v0.2
  for parsing windows pe structure, adjust realoc addrs, or iat

  history:
  v0.1 initial version, with load pe in memory align
  V0.1.2 adjust declear name, load pe iat
  v0.2 add append section, findiat function

*/

#ifndef _WINPE_H
#define _WINPE_H
#include <stdint.h>
#include <Windows.h>

#ifndef WINPEDEF
#ifdef WINPE_STATIC
#define WINPEDEF static
#else
#define WINPEDEF extern
#endif
#endif

#ifndef WINPE_SHARED
#define WINPE_EXPORT
#else
#ifdef _WIN32
#define WINPE_EXPORT __declspec(dllexport)
#else
#define WINPE_EXPORT __attribute__((visibility("default")))
#endif
#endif

#ifdef __cplusplus
extern "C" {
#endif
typedef struct _RELOCOFFSET
{
	WORD offset : 12;
	WORD type	: 4;
}RELOCOFFSET,*PRELOCOFFSET;

typedef int bool_t;

typedef HMODULE (WINAPI *PFN_LoadLibraryA)(
    LPCSTR lpLibFileName);

typedef FARPROC (WINAPI *PFN_GetProcAddress)(
    HMODULE hModule, LPCSTR lpProcName);

// PE functions
/*
  load the overlay data in a pe file
    return overlay buf, overlay size
*/
WINPEDEF WINPE_EXPORT 
void* winpe_overlayload_file(const char *path, 
    size_t *poverlaysize);

/*
  for overlay section in a pe file
    return the overlay offset
*/
WINPEDEF WINPE_EXPORT 
size_t winpe_overlayoffset(const void *rawpe);

/*
  load the origin rawpe file in memory buffer by mem align
    return mempe buffer, memsize
*/
WINPEDEF WINPE_EXPORT 
void* winpe_memload_file(const char *path, 
    size_t *pmemsize, bool_t same_align);

/*
  load the origin rawpe in memory buffer by mem align
    return memsize
*/
WINPEDEF WINPE_EXPORT 
size_t winpe_memload(const void *rawpe, size_t rawsize, 
    void *mempe, size_t memsize, bool_t same_align);

/*
  realoc the addrs for the mempe addr as image base
    return realoc count
*/
WINPEDEF WINPE_EXPORT 
size_t winpe_memreloc(void *mempe, size_t newimagebase);

/*
  load the iat for the mempe
    return iat count
*/
WINPEDEF WINPE_EXPORT 
size_t winpe_membindiat(void *mempe, 
    PFN_LoadLibraryA pfnLoadLibraryA, 
    PFN_GetProcAddress pfnGetProcAddress);

/*
  find the iat addres, for call [iat]
    return target iat rva
*/
WINPEDEF WINPE_EXPORT 
size_t winpe_memfindiat(void *mempe, 
    LPCSTR dllname, LPCSTR funcname);

/* 
  change the oep of the pe if newoeprva!=0
    return the old oep rva
*/
WINPEDEF WINPE_EXPORT
DWORD winpe_setoep(void *mempe, DWORD newoeprva);

/*
    close the aslr feature of an pe
*/
WINPEDEF WINPE_EXPORT
void winpe_noaslr(void *pe);

/* 
  Append a section header in a pe, sect rva will be ignored
  the mempe size must be enough for extend a section
    return image size
*/
WINPEDEF WINPE_EXPORT 
size_t winpe_appendsecth(void *mempe, 
    PIMAGE_SECTION_HEADER psecth);


#ifdef __cplusplus
}
#endif


#ifdef WINPE_IMPLEMENTATION
#include <stdio.h>
#include <Windows.h>

// PE functions
WINPEDEF WINPE_EXPORT 
void* winpe_overlayload_file(const char *path, 
    size_t *poverlaysize)
{
    FILE *fp = fopen(path, "rb");
    fseek(fp, 0, SEEK_END);
    size_t rawsize = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    void *rawpe = malloc(rawsize);
    fread(rawpe, 1, rawsize, fp);
    fclose(fp);
    void *overlay = NULL;
    size_t overlayoffset = winpe_overlayoffset(rawpe);
    
    if(poverlaysize)
    {
        *poverlaysize = rawsize - overlayoffset;
        if(*poverlaysize>0)
        {
            overlay = malloc(*poverlaysize);
            memcpy(overlay, rawpe+overlayoffset, *poverlaysize);
        }
    }
    free(rawpe);
    return overlay;
}

WINPEDEF WINPE_EXPORT 
size_t winpe_overlayoffset(const void *rawpe)
{
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)rawpe;
    PIMAGE_NT_HEADERS  pNtHeader = (PIMAGE_NT_HEADERS)
        ((void*)rawpe + pDosHeader->e_lfanew);
    PIMAGE_FILE_HEADER pFileHeader = &pNtHeader->FileHeader;
    PIMAGE_OPTIONAL_HEADER pOptHeader = &pNtHeader->OptionalHeader;
    PIMAGE_DATA_DIRECTORY pDataDirectory = pOptHeader->DataDirectory;
    PIMAGE_SECTION_HEADER pSectHeader = (PIMAGE_SECTION_HEADER)
        ((void*)pOptHeader + pFileHeader->SizeOfOptionalHeader);
    WORD sectNum = pFileHeader->NumberOfSections;

    return pSectHeader[sectNum-1].PointerToRawData + 
           pSectHeader[sectNum-1].SizeOfRawData;
}

WINPEDEF WINPE_EXPORT 
void* winpe_memload_file(const char *path, 
    size_t *pmemsize, bool_t same_align)
{
    FILE *fp = fopen(path, "rb");
    fseek(fp, 0, SEEK_END);
    size_t rawsize = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    void *rawpe = malloc(rawsize);
    fread(rawpe, 1, rawsize, fp);
    fclose(fp);

    void *mempe = NULL;
    if(pmemsize)
    {
        *pmemsize = winpe_memload(rawpe, 0, NULL, 0, FALSE);
        mempe = malloc(*pmemsize);
        winpe_memload(rawpe, rawsize, mempe, *pmemsize, same_align);
    }
    free(rawpe);
    return mempe;
}

WINPEDEF WINPE_EXPORT 
size_t winpe_memload(const void *rawpe, size_t rawsize, 
    void *mempe, size_t memsize, bool_t same_align)
{
    // load rawpe to memalign
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)rawpe;
    PIMAGE_NT_HEADERS  pNtHeader = (PIMAGE_NT_HEADERS)
        ((void*)rawpe + pDosHeader->e_lfanew);
    PIMAGE_FILE_HEADER pFileHeader = &pNtHeader->FileHeader;
    PIMAGE_OPTIONAL_HEADER pOptHeader = &pNtHeader->OptionalHeader;
    PIMAGE_SECTION_HEADER pSectHeader = (PIMAGE_SECTION_HEADER)
        ((void *)pOptHeader + pFileHeader->SizeOfOptionalHeader);
    WORD sectNum = pFileHeader->NumberOfSections;
    size_t imagesize = pOptHeader->SizeOfImage;
    if(!mempe) return imagesize;
    else if(memsize!=0 && memsize<imagesize) return 0;

    memset(mempe, 0, imagesize);
    memcpy(mempe, rawpe, pOptHeader->SizeOfHeaders);
    
    for(WORD i=0;i<sectNum;i++)
    {
        memcpy(mempe+pSectHeader[i].VirtualAddress, 
            rawpe+pSectHeader[i].PointerToRawData,
            pSectHeader[i].SizeOfRawData);
    }

    // adjust all to mem align
    if(same_align)
    {
        pDosHeader = (PIMAGE_DOS_HEADER)mempe;
        pNtHeader = (PIMAGE_NT_HEADERS)((void*)mempe + pDosHeader->e_lfanew);
        pFileHeader = &pNtHeader->FileHeader;
        pOptHeader = &pNtHeader->OptionalHeader;
        pSectHeader = (PIMAGE_SECTION_HEADER)
            ((void *)pOptHeader + pFileHeader->SizeOfOptionalHeader);
        sectNum = pFileHeader->NumberOfSections;

        pOptHeader->FileAlignment = pOptHeader->SectionAlignment;

        for(WORD i=0;i<sectNum;i++)
        {
            pSectHeader[i].PointerToRawData = pSectHeader[i].VirtualAddress;
        }
    }
    return imagesize;
}

WINPEDEF WINPE_EXPORT 
size_t winpe_memreloc(void *mempe, size_t newimagebase)
{
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)mempe;
    PIMAGE_NT_HEADERS  pNtHeader = (PIMAGE_NT_HEADERS)
        ((void*)mempe + pDosHeader->e_lfanew);
    PIMAGE_FILE_HEADER pFileHeader = &pNtHeader->FileHeader;
    PIMAGE_OPTIONAL_HEADER pOptHeader = &pNtHeader->OptionalHeader;
    PIMAGE_DATA_DIRECTORY pDataDirectory = pOptHeader->DataDirectory;
    PIMAGE_DATA_DIRECTORY pRelocEntry = &pDataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	
    DWORD reloc_count = 0;
	DWORD reloc_offset = 0;
    int64_t shift = (int64_t)newimagebase - 
        (int64_t)pOptHeader->ImageBase;
	while (reloc_offset < pRelocEntry->Size)
	{
		PIMAGE_BASE_RELOCATION pBaseReloc = (PIMAGE_BASE_RELOCATION)
            ((void*)mempe + pRelocEntry->VirtualAddress + reloc_offset);
        PRELOCOFFSET pRelocOffset = (PRELOCOFFSET)((void*)pBaseReloc 
            + sizeof(IMAGE_BASE_RELOCATION));
		DWORD item_num = (pBaseReloc->SizeOfBlock - // RELOCOFFSET block num
			sizeof(IMAGE_BASE_RELOCATION)) / sizeof(RELOCOFFSET);
		for (size_t i = 0; i < item_num; i++)
		{
			if (!pRelocOffset[i].type && 
                !pRelocOffset[i].offset) continue;
			DWORD targetoffset = pBaseReloc->VirtualAddress + 
                    pRelocOffset[i].offset;
            size_t *paddr = (size_t *)((void*)mempe + targetoffset);
            size_t relocaddr = (size_t)((int64_t)*paddr + shift);
            //printf("reloc 0x%08x->0x%08x\n", *paddr, relocaddr);
            *paddr = relocaddr;
		}
		reloc_offset += sizeof(IMAGE_BASE_RELOCATION) + 
            sizeof(RELOCOFFSET) * item_num;
		reloc_count += item_num;
	}
    pOptHeader->ImageBase = newimagebase;
	return reloc_count;
}

WINPEDEF WINPE_EXPORT 
size_t winpe_membindiat(void *mempe, 
    PFN_LoadLibraryA pfnLoadLibraryA, 
    PFN_GetProcAddress pfnGetProcAddress)
{
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)mempe;
    PIMAGE_NT_HEADERS  pNtHeader = (PIMAGE_NT_HEADERS)
        ((void*)mempe + pDosHeader->e_lfanew);
    PIMAGE_FILE_HEADER pFileHeader = &pNtHeader->FileHeader;
    PIMAGE_OPTIONAL_HEADER pOptHeader = &pNtHeader->OptionalHeader;
    PIMAGE_DATA_DIRECTORY pDataDirectory = pOptHeader->DataDirectory;
    PIMAGE_DATA_DIRECTORY pImpEntry =  
        &pDataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    PIMAGE_IMPORT_DESCRIPTOR pImpDescriptor =  
        (PIMAGE_IMPORT_DESCRIPTOR)(mempe + pImpEntry->VirtualAddress);

    PIMAGE_THUNK_DATA pFtThunk = NULL;
    PIMAGE_THUNK_DATA pOftThunk = NULL;
    LPCSTR pDllName = NULL;
    PIMAGE_IMPORT_BY_NAME pFuncName = NULL;

    if(!pfnLoadLibraryA) pfnLoadLibraryA = LoadLibraryA;
    if(!pfnGetProcAddress) pfnGetProcAddress = GetProcAddress;
    DWORD iat_count = 0;
    for (; pImpDescriptor->Name; pImpDescriptor++) 
    {
        pDllName = (LPCSTR)(mempe + pImpDescriptor->Name);
        pFtThunk = (PIMAGE_THUNK_DATA)
            (mempe + pImpDescriptor->FirstThunk);
        pOftThunk = (PIMAGE_THUNK_DATA)
            (mempe + pImpDescriptor->OriginalFirstThunk);
        HMODULE hmod = pfnLoadLibraryA(pDllName);
        if(!hmod) return 0;

        for (int j=0; pFtThunk[j].u1.Function 
            &&  pOftThunk[j].u1.Function; j++) 
        {
            PROC addr = NULL;
			if((pOftThunk[j].u1.Ordinal >>31) != 0x1) // use name
			{
				pFuncName=(PIMAGE_IMPORT_BY_NAME)(mempe +
                    pOftThunk[j].u1.AddressOfData);
                addr = pfnGetProcAddress(hmod, pFuncName->Name);

			}
			else // use ordinal
			{
				addr =GetProcAddress(hmod, 
                (LPCSTR)(pOftThunk[j].u1.Ordinal & 0x0000ffff));
			}
            if(!addr) return 0;
            pFtThunk[j].u1.Function = (size_t)addr;
            iat_count++;
        }
    }
    return iat_count;
}

WINPEDEF WINPE_EXPORT 
size_t winpe_memfindiat(void *mempe, 
    LPCSTR dllname, LPCSTR funcname)
{
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)mempe;
    PIMAGE_NT_HEADERS  pNtHeader = (PIMAGE_NT_HEADERS)
        ((void*)mempe + pDosHeader->e_lfanew);
    PIMAGE_FILE_HEADER pFileHeader = &pNtHeader->FileHeader;
    PIMAGE_OPTIONAL_HEADER pOptHeader = &pNtHeader->OptionalHeader;
    PIMAGE_DATA_DIRECTORY pDataDirectory = pOptHeader->DataDirectory;
    PIMAGE_DATA_DIRECTORY pImpEntry =  
        &pDataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    PIMAGE_IMPORT_DESCRIPTOR pImpDescriptor =  
        (PIMAGE_IMPORT_DESCRIPTOR)(mempe + pImpEntry->VirtualAddress);

    PIMAGE_THUNK_DATA pFtThunk = NULL;
    PIMAGE_THUNK_DATA pOftThunk = NULL;
    LPCSTR pDllName = NULL;
    PIMAGE_IMPORT_BY_NAME pFuncName = NULL;

    for (; pImpDescriptor->Name; pImpDescriptor++) 
    {
        pDllName = (LPCSTR)(mempe + pImpDescriptor->Name);
        if(dllname && _stricmp(pDllName, dllname)!=0) continue;
        pFtThunk = (PIMAGE_THUNK_DATA)
            (mempe + pImpDescriptor->FirstThunk);
        pOftThunk = (PIMAGE_THUNK_DATA)
            (mempe + pImpDescriptor->OriginalFirstThunk);

        for (int j=0; pFtThunk[j].u1.Function 
            &&  pOftThunk[j].u1.Function; j++) 
        {
			if((pOftThunk[j].u1.Ordinal >>31) != 0x1) // use name
			{
				pFuncName=(PIMAGE_IMPORT_BY_NAME)(mempe +
                    pOftThunk[j].u1.AddressOfData);
                if(_stricmp(pFuncName->Name, funcname)==0) 
                    return (size_t)&pFtThunk[j] - (size_t)mempe;
			}
        }
    }
    return 0;
}

WINPEDEF WINPE_EXPORT
void winpe_noaslr(void *pe)
{
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pe;
    PIMAGE_NT_HEADERS  pNtHeader = (PIMAGE_NT_HEADERS)
        ((void*)pe + pDosHeader->e_lfanew);
    PIMAGE_FILE_HEADER pFileHeader = &pNtHeader->FileHeader;
    PIMAGE_OPTIONAL_HEADER pOptHeader = &pNtHeader->OptionalHeader;
    pOptHeader->DllCharacteristics &= ~IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE;
}

WINPEDEF WINPE_EXPORT
DWORD winpe_setoep(void *pe, DWORD newoeprva)
{
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pe;
    PIMAGE_NT_HEADERS  pNtHeader = (PIMAGE_NT_HEADERS)
        ((void*)pe + pDosHeader->e_lfanew);
    PIMAGE_FILE_HEADER pFileHeader = &pNtHeader->FileHeader;
    PIMAGE_OPTIONAL_HEADER pOptHeader = &pNtHeader->OptionalHeader;
    DWORD orgoep = pOptHeader->AddressOfEntryPoint;
    if(newoeprva) pOptHeader->AddressOfEntryPoint = newoeprva;
    return orgoep;
}

WINPEDEF WINPE_EXPORT 
size_t winpe_appendsecth(void *pe, 
    PIMAGE_SECTION_HEADER psecth)
{
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pe;
    PIMAGE_NT_HEADERS  pNtHeader = (PIMAGE_NT_HEADERS)
        ((void*)pe + pDosHeader->e_lfanew);
    PIMAGE_FILE_HEADER pFileHeader = &pNtHeader->FileHeader;
    PIMAGE_OPTIONAL_HEADER pOptHeader = &pNtHeader->OptionalHeader;
    PIMAGE_SECTION_HEADER pSectHeader = (PIMAGE_SECTION_HEADER)
        ((void*)pOptHeader + pFileHeader->SizeOfOptionalHeader);
    WORD sectNum = pFileHeader->NumberOfSections;
    PIMAGE_SECTION_HEADER pLastSectHeader = &pSectHeader[sectNum-1];
    DWORD addr, align;

    // check the space to append section
    if(pFileHeader->SizeOfOptionalHeader 
        + sizeof(IMAGE_SECTION_HEADER)
     > pSectHeader[0].PointerToRawData) return 0;

    // fill rva addr
    align = pOptHeader->SectionAlignment;
    addr = pLastSectHeader->VirtualAddress + pLastSectHeader->Misc.VirtualSize;
    if(addr % align) addr += align - addr%align;
    psecth->VirtualAddress = addr;

    // fill file offset
    align = pOptHeader->FileAlignment;
    addr =  pLastSectHeader->PointerToRawData+ pLastSectHeader->SizeOfRawData;
    if(addr % align) addr += align - addr%align;
    psecth->PointerToRawData = addr;

    // adjust the section and imagesize 
    pFileHeader->NumberOfSections++;
    memcpy(&pSectHeader[sectNum], psecth, sizeof(IMAGE_SECTION_HEADER));
    align = pOptHeader->SectionAlignment;
    addr = psecth->VirtualAddress + psecth->Misc.VirtualSize;
    if(addr % align) addr += align - addr%align;
    pOptHeader->SizeOfImage = addr; 
    return pOptHeader->SizeOfImage;
}

#endif
#endif