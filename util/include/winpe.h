/*
  winpe.h, by devseed, v0.1
  for parsing windows pe structure, adjust realoc addrs, or iat

  history:
  v0.1 initial version, with load pe in memory align

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

// PE functions
/*
  returns the overlay offset in a pe file
*/
WINHOOKDEF WINHOOK_EXPORT 
size_t winpe_overlayoffset(const void *rawpe);

/*
  load the origin rawpe in memory buffer by mem align
    returns memsize
*/
WINHOOKDEF WINHOOK_EXPORT 
size_t winpe_memload(const void *rawpe, size_t rawsize, 
    void *mempe, size_t memsize, bool_t same_align);

/*
  realoc the addrs for the mempe addr as image base
    returns realoc count
*/
WINHOOKDEF WINHOOK_EXPORT 
size_t winpe_memreloc(void *mempe, size_t newimagebase);

/*
  load the iat for the mempe
    returns iat count
*/
WINHOOKDEF WINHOOK_EXPORT 
size_t winpe_memiat(void *mempe);

#ifdef __cplusplus
}
#endif


#ifdef WINPE_IMPLEMENTATION
#include <Windows.h>

// PE functions
WINHOOKDEF WINHOOK_EXPORT 
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

WINHOOKDEF WINHOOK_EXPORT 
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

WINHOOKDEF WINHOOK_EXPORT 
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

WINHOOKDEF WINHOOK_EXPORT 
size_t winpe_memiat(void *mempe)
{
    return 0;
}
#endif
#endif