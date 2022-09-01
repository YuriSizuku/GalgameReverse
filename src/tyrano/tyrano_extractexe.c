#include<stdio.h>
#include<windows.h>

#ifdef _WIN64
#define ADDR_TYPE DWORD
#else
#define ADDR_TYPE ULONGLONG
#endif
#define MAX_BUF 0x1000

size_t getOverlayRawoffset(BYTE *pe)
{
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pe;
    
    PIMAGE_NT_HEADERS  pNtHeader = (PIMAGE_NT_HEADERS)
        ((ADDR_TYPE)pe + pDosHeader->e_lfanew);
    PIMAGE_FILE_HEADER pFileHeader = &pNtHeader->FileHeader;
    PIMAGE_OPTIONAL_HEADER pOptHeader = &pNtHeader->OptionalHeader;
    PIMAGE_DATA_DIRECTORY pDataDirectory = pOptHeader->DataDirectory;
 
    PIMAGE_SECTION_HEADER pSectHeader = (PIMAGE_SECTION_HEADER)
        ((ADDR_TYPE)pOptHeader + pFileHeader->SizeOfOptionalHeader);
    WORD sectNum = pFileHeader->NumberOfSections;

    // printf("pNtHeader = %llx\n", (ADDR_TYPE)pNtHeader - (ADDR_TYPE)pe);
    // printf("pSectHeader = %llx\n", (ADDR_TYPE)pSectHeader - (ADDR_TYPE)pe);
    // printf("lastsect PointerToRawData=%lx, SizeOfRawData=%lx\n", 
    //     pSectHeader[sectNum-1].PointerToRawData, 
    //     pSectHeader[sectNum-1].SizeOfRawData);
    return pSectHeader[sectNum-1].PointerToRawData + 
           pSectHeader[sectNum-1].SizeOfRawData;
}

void extractOverlay(const char *inpath, const char *outpath)
{
    BYTE buf[MAX_BUF];
    FILE* fpin = fopen(inpath, "rb");
    FILE* fpout = fopen(outpath, "wb");
    
    fread(buf, MAX_BUF, 1, fpin);
    size_t offset = getOverlayRawoffset(buf);
    //printf("overlay offset at %zx\n", offset);
    fseek(fpin, offset, SEEK_SET);
    int ch;
    while((ch=fgetc(fpin))!=EOF)
    {
        fputc(ch, fpout);
    }
    fclose(fpout);
    fclose(fpin);
}

int main(int argc, char *argv[])
{
    printf("A tool to extract tyrano build-in exe files, by devseed\n");
    if(argc<2)
    {
        printf("tyrano_extract_exe exepath [outpath]\n");
    }
    char outpath[MAX_BUF];
    if(argc<3)
    {
        strcpy(outpath, argv[1]);
        strcat(outpath, ".zip");
    }
    else
    {
        strcpy(outpath, argv[2]);
    }
    printf("to extract %s ...\n", argv[1]);
    extractOverlay(argv[1], outpath);
    printf("extract to %s finished!\n", outpath);
}