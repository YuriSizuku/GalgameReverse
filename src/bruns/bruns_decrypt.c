/*
    This is for decrypt EENZ files, DustmaniaGrotesque tested 
    v0.1, by devseed
*/
#include <stdio.h>
#include <locale.h>
#include <Windows.h>
#pragma pack(1)
struct decrypt_buf
{
    DWORD unkown1; 
    char *bufstart;
    char *bufend;
    char *bufend2;
};

struct wstring
{
    size_t capability;
    union //0x4
    {
       wchar_t *extern_buf;
       wchar_t buf[10];
    };
    size_t capability2; // 0x18
};

typedef int(*file_to_bytearray_nosearch)(struct decrypt_buf* a1, struct wstring* a2);

void bruns_decrypt(char* inpath, char* outpath)
{
    wchar_t inpathw[256] = {0};
    mbstowcs(inpathw, inpath, 256);
 
    struct decrypt_buf a1 = {0};
    struct wstring a2 ={0};
    a2.capability = 0x190;
    a2.extern_buf = inpathw;
    a2.capability2 = 0x17;

    HMODULE hMod = LoadLibraryA("libscr.dll");
    if(!hMod)
    {
        printf("error: can not load libscr.dll\n");
        return;
    }
    file_to_bytearray_nosearch pfunc = (file_to_bytearray_nosearch)GetProcAddress(hMod, 
    "?file_to_bytearray_nosearch@SepterEnv@@SA_NAAV?$vector_mtus@E@@ABV?$basic_string@_WU?$char_traits@_W@std@@V?$allocator@_W@2@@std@@@Z");
    if(!pfunc)
    {
        printf("error: can not find file_to_bytearray_nosearch\n");
        return;
    }
    pfunc(&a1, &a2);
    if(a1.bufstart && a1.bufend-a1.bufstart>0)
    {
        FILE* fp = fopen(outpath, "wb");
        size_t size = a1.bufend-a1.bufstart;
        fwrite(a1.bufstart, 1, size, fp);
        printf("%x bytes decrypted to %s!\n", size, outpath);
        fclose(fp);
    }
    FreeLibrary(hMod);
}

int main(int argc, char** argv)
{
    if(argc<2)
    {
        printf("bruns_decrypt input [output]\n");
        return 0;
    }
    char outpath[256];
    if(argc>2)
    {
        strcpy(outpath, argv[2]);
    }
    else
    {
        strcpy(outpath, argv[1]);
        strcat(outpath, ".txt");
    }
    bruns_decrypt(argv[1], outpath);
    return 0;
}