/**
 *  for lamune.exe v1.0  (azsystem) chs support
 *  v0.2.1, developed by devseed
 *  
*/

#include <windows.h>
#include <stdio.h>
#define WINHOOK_IMPLEMENTATION
#define WINHOOK_NOINLINEHOOK
#include "winhook.h"
#define WINPE_IMPLEMENTATION
#define WINPE_NOASM
#include "winpe.h"
#define STB_IMAGE_IMPLEMENTATION

// for fix xp threadlocal loadlibrary problem
#define STBI_NO_THREAD_LOCALS
#include "stb_image.h"
#define ZIP_IMPLEMENTATION
#include "zip.h"

#define STDCALL __stdcall
#define NAKED __declspec(naked)
#define REGISTER_HOOK(name, addr) const g_##name##_##addr=0x##addr

#define SCENERIO_DIR "scenario_chs"
#define SYSGRAPH_DIR "sysgraph_chs"
#define SYSGRAPH_EXT ".png"

/* for hook new decompressed buffer
0043119A   | FF75 E0   | push dword ptr ss:[ebp-20]
0043119D   | E8 A1510000  | call lamune.436343 | new
004311A2   | FF75 E4    | push dword ptr ss:[ebp-1C]  | [ebp-1c] raw_size
004311A5   | 8945 F0  | mov dword ptr ss:[ebp-10],eax
004311A8   | E8 96510000         | call lamune.436343  | new raw_buf
*/
const DWORD g_newrawbufi_4311A2 = 0x4311A2;
const DWORD g_newrawbufo_4311A8 = 0x4311A8;

/* for hook decompress asb
.text:004311D4 FF 75 E4          push    [ebp+raw_size]  ; raw_len
.text:004311D7 8D 4D EC          lea     ecx, [ebp+var_14]
.text:004311DA 57                push    edi             ; raw_data
.text:004311DB FF 75 E0    push [ebp+compressed_size] ; compressed_len
.text:004311DE FF 75 F0    push [ebp+compressed_data] ; compressed_data
.text:004311E1 E8 7F 99 FD FF    call    decompress_40AB65
*/
const DWORD g_decompressasbi_4311E1 = 0x4311E1;
const DWORD g_decompressasbo_40AB65 = 0x40AB65;

/*  for hook loadcpb, save cpbname
.text:00419E04 8B EC             mov     ebp, esp
.text:00419E06 83 EC 2C          sub     esp, 2Ch
.text:00419E09 53                push    ebx
.text:00419E0A 56                push    esi
.text:00419E0B 33 DB             xor     ebx, ebx
.text:00419E0D 39 5D 08          cmp     [ebp+filename], ebx
*/
const char* g_curcpbname = NULL;
const DWORD g_loadcpbi_419E03 = 0x419E03;
const DWORD g_loadcpbo_419E09 = 0x419E09;

/* for hook decompressed cpb24 buffer
0041E2DB   | 8B55 0C  | mov edx,dword ptr ss:[ebp+C]
0041E2DE   | 8BC7   | mov eax,edi 
0041E2E0   | 2BC6   | sub eax,esi
0041E2E2   | 42   | inc edx 
0041E2E3   | 8955 0C  | mov dword ptr ss:[ebp+C],edx
0041E2E6   | 894D EC  | mov dword ptr ss:[ebp-14],ecx
0041E2E9   | 85DB | test ebx,ebx 
0041E2EB   | 7E 35 | jle lamune_chs.41E322 
*/
const DWORD g_copycpb24i_41E2DB = 0x41E2DB;
const DWORD g_copycpb24o_41E2E0 = 0x41E2E0;

/* for hook decompressed cpb32 buffer
0041E4C6   | 8B45 E4 | mov eax,dword ptr ss:[ebp-1C]                     
0041E4C9   | 85C0   | test eax,eax
0041E4CB < | 0F8E 83000000 | jle lamune_chs.41E554 
*/
const DWORD g_copycpb32i_41E4C6 = 0x41E4C6;
const DWORD g_copycpb32o_41E4CB = 0x41E4CB;

/* for hook decompressed cpb32 2 buffer
0041DEFD   | 8B45 DC  | mov eax,dword ptr ss:[ebp-24]
0041DF00   | 85C0      |test eax,eax
0041DF02   | 0F8E 83000000 | jle lamune_chs.41DF8B
*/
const DWORD g_copycpb32i_41DEFD = 0x41DEFD;
const DWORD g_copycpb32o_41DF02 = 0x41DF02;


__declspec(dllexport) void dummy()
{

}

// load function
size_t __stdcall load_arc_entry(char *path, PBYTE buf)
{
    size_t decasb_size = 0;
    FILE *fp = fopen(path, "rb");
    if(fp)
    {
        fseek(fp, 0, SEEK_END);
        decasb_size = ftell(fp);
        if(buf)
        {
            fseek(fp, 0, SEEK_SET);
            fread(buf, 1, decasb_size, fp);
        }
        fclose(fp);
    }
    else 
    {// try to load in zip file
#ifdef ZIP_IMPLEMENTATION
        static HANDLE s_hfile= NULL;
        static HANDLE s_hmap = NULL;
        static size_t s_zipsize = 0;
        static char* s_zipbuf = NULL;
        static struct zip_t *s_zip =NULL;
        
        if(!s_hfile)
        {
            char exepath[MAX_PATH];
            GetModuleFileNameA(NULL, exepath, sizeof(exepath));
            strcpy(&exepath[strlen(exepath)-4], ".dvfs\0");
            s_hfile = CreateFileA(exepath, GENERIC_READ, // load dec file
                FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
            if (s_hfile != INVALID_HANDLE_VALUE) 
            {
                s_hmap = CreateFileMappingA(s_hfile, NULL, 
                    PAGE_READONLY, 0, 0, NULL);
                s_zipsize = GetFileSize(s_hfile, NULL);
                s_zipbuf = MapViewOfFile(s_hmap, FILE_MAP_READ, 0, 0, 0);
            }
            else // load pe overlay
            {
                strcpy(&exepath[strlen(exepath)-5], ".exe\0");
                s_hfile = CreateFileA(exepath, GENERIC_READ, 
                    FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
                s_zipsize = GetFileSize(s_hfile, NULL);
                s_hmap = CreateFileMappingA(s_hfile, NULL, 
                    PAGE_READONLY, 0, 0, NULL);
                s_zipbuf = MapViewOfFile(s_hmap, FILE_MAP_READ, 0, 0, 0);
                size_t zipoff = winpe_overlayoffset((BYTE*)s_zipbuf);
                s_zipbuf += zipoff;
                s_zipsize -= zipoff;
            }
            printf("\nuse %s for loading arc\n", exepath);
        }
    
        if (!s_zip)
        {
            s_zip = zip_stream_open(s_zipbuf, s_zipsize, 0, 'r');
        }
        if (!zip_entry_open(s_zip, path)) // return 0 on success
        {
            decasb_size = zip_entry_size(s_zip);
            if (buf)
            {
                zip_entry_noallocread(s_zip, buf, decasb_size);
            }
            zip_entry_close(s_zip);
        }
#endif
    }
    return decasb_size;
}

size_t __stdcall load_rawasb(char *name, PBYTE buf)
{
    char path[MAX_PATH] = {SCENERIO_DIR "/" "\0"};
    strcat(path, name);
    size_t decasb_size =  load_arc_entry(path, buf);
    printf("load_rawasb(%s, %p) with size %06X\n", 
        path, buf, decasb_size);
    return decasb_size;
}

size_t __stdcall load_rawcpb(char *name, PBYTE buf)
{
    char path[MAX_PATH] = {SYSGRAPH_DIR "/" "\0"};
    strcat(path, name);
    strcpy(path + strlen(path)-strlen(SYSGRAPH_EXT),SYSGRAPH_EXT);

    int width, height, channel;
    printf("load_rawcpb(%s, %p)", path, buf);
    size_t entry_size = load_arc_entry(path, NULL);
    const BYTE *tmpbuf = (BYTE*)malloc(entry_size);
    load_arc_entry(path, (PBYTE)tmpbuf);
    char* img = (char*)stbi_load_from_memory(tmpbuf, 
        entry_size, &width, &height, &channel, 0);
    free((void*)tmpbuf);
    
    if(!img) 
    {
        printf(" not found!\n");
        return 0;
    }
    printf(" width=%d, heigth=%d, channel=%d\n",
        width, height, channel);
    for(int y=0;y<height;y++)
    {
        for(int x=0;x<width;x++)
        {
            char r = *(img + channel * (width*y + x) + 0);
            char g = *(img + channel * (width*y + x) + 1);
            char b = *(img + channel * (width*y + x) + 2);
            

            *(buf + 0*height*width + width*y+x) = r;
            *(buf + 1*height*width + width*y+x) = g;
            *(buf + 2*height*width + width*y+x) = b;
            if(channel==4)
            {
                char a = *(img + channel * (width*y + x) + 3); 
                *(buf + 3*height*width + width*y+x) = a;
            }
        }
    }

    stbi_image_free(img);
    return width*height*channel;
}

// inlinehook stubs
void __declspec(naked) newrawbuf_hook_4311A2()
{
    __asm{
        pushad;
        xor eax, eax;
        push eax;
        push [ebp+8];
        call load_rawasb;
        test eax, eax;
        je newrawbuf_hook_end;
        mov [ebp-0x1c], eax; // change raw buf size
        newrawbuf_hook_end:
        popad;
        
        // fix origin code
        push dword ptr [ebp-0x1c]; 
        mov dword ptr [ebp-0x10], eax;
        jmp dword ptr ds:[g_newrawbufo_4311A8];
    } 
}

void __declspec(naked) decompressasb_hook_4311E1()
{
    //sub_40AB65(char *compressed_data, int compressed_len, char *raw_data, int raw_len)
    __asm {
        push [esp+0xc]; // after push ret addr, above, raw_buf
        push [ebp+0x8];  // asbname
        call load_rawasb;
        test eax, eax;
        je decompress_origin;
        ret 0x10;
        decompress_origin:
        mov eax, 0x99E15CB4; // this is the original corrent crc value
        mov dword ptr ds:[0x0047E718], eax; // this is not worked...
        jmp dword ptr ds:[g_decompressasbo_40AB65];
    }
}

void __declspec(naked) loadcpb_hook_419E03()
{
    __asm {
        push eax;
        mov eax, dword ptr [esp+8]; // after push eax
        mov g_curcpbname, eax;
        pop eax;
        
        // fix origin code
        push ebp;
        mov ebp, esp;
        sub esp, 0x2c;
        jmp dword ptr ds:[g_loadcpbo_419E09];
    }
}

void __declspec(naked) copycpb24_hook_41E2DB()
{
    __asm {
        pushad;
        push [ebp-0x20];
        push g_curcpbname;
        call load_rawcpb;
        popad;
        // fix origin code
        mov edx,dword ptr [ebp+0xC];
        mov eax,edi;
        jmp dword ptr ds:[g_copycpb24o_41E2E0];
    }
}

void __declspec(naked) copycpb32_hook_41E4C6()
{
    __asm {
        pushad;
        push [ebp-0x20];
        push g_curcpbname;
        call load_rawcpb;
        popad;
        // fix origin code
        mov eax, dword ptr [ebp-0x1c];
        test eax,eax;
        jmp dword ptr ds:[g_copycpb32o_41E4CB];
    }
}

void __declspec(naked) copycpb32_hook_41DEFD()
{
    __asm {
        pushad;
        push [ebp-0x20];
        push g_curcpbname;
        call load_rawcpb;
        popad;
        // fix origin code
        mov eax, dword ptr [ebp-0x24];
        test eax,eax;
        jmp dword ptr ds:[g_copycpb32o_41DF02];
    }
}

// iat hook function
HFONT WINAPI CreateFontA_hook(int cHeight, int cWidth, 
    int cEscapement, int cOrientation, int cWeight, DWORD bItalic,
    DWORD bUnderline, DWORD bStrikeOut, DWORD iCharSet,  
    DWORD iOutPrecision, DWORD iClipPrecision,
    DWORD iQuality, DWORD iPitchAndFamily, LPCSTR pszFaceName)
{
    iCharSet = GB2312_CHARSET;
    return CreateFontA(cHeight, cWidth, 
        cEscapement, cOrientation, cWeight, bItalic, 
        bUnderline, bStrikeOut, iCharSet, 
        iOutPrecision, iClipPrecision, 
        iQuality, iPitchAndFamily, pszFaceName);
}

int WINAPI EnumFontFamiliesExA_hook(HDC hdc, 
    LPLOGFONTA lpLogfont, FONTENUMPROCA lpProc,  
    LPARAM lParam, DWORD dwFlags)
{
    lpLogfont->lfCharSet = GB2312_CHARSET;
    return EnumFontFamiliesExA(hdc, lpLogfont, lpProc, lParam, dwFlags);
}

// hook install functions
void install_asbhook()
{
    /* inlinehook check_valid
    004311BF   | FF75 E4             | push dword ptr ss:[ebp-1C]                         |
    004311C2   | 8BCE                | mov ecx,esi                                        | esi:&"&CB"
    004311C4   | FF75 E0             | push dword ptr ss:[ebp-20]                         |
    004311C7   | FF75 F0             | push dword ptr ss:[ebp-10]                         |
    004311CA   | E8 9BFDFFFF         | call lamune.430F6A                                 |
    004311CF   | 83F8 01             | cmp eax,1                                          | eax:"0nana.asb"
    004311D2   | 75 3C               | jne lamune.431210                                  |

    .text:0040AB8A 6A 00             push    0
    .text:0040AB8C 8D 43 FC          lea     eax, [ebx-4]
    .text:0040AB8F 50                push    eax
    .text:0040AB90 8D 77 04          lea     esi, [edi+4]
    .text:0040AB93 56                push    esi
    .text:0040AB94 E8 27 D9 FF FF    call    makecrc_4084C0
    .text:0040AB99 83 C4 0C          add     esp, 0Ch
    .text:0040AB9C 39 07             cmp     [edi], eax
    .text:0040AB9E 75 64             jnz     short loc_40AC04
    */
    BYTE nop2[0x2]={0x90, 0x90};
    winhook_patchmemory((LPVOID)0x4311d2, 
        nop2, sizeof(nop2));
    winhook_patchmemory((LPVOID)0x40AB9E, 
        nop2, sizeof(nop2));
    
    // inlinehook newrawdata
    BYTE jmpE8buf[0x5]={0xE9}; // jmp relative
    *(DWORD*)(jmpE8buf+1) = (DWORD)newrawbuf_hook_4311A2-  
        ((DWORD)g_newrawbufi_4311A2 + sizeof(jmpE8buf));
    winhook_patchmemory((LPVOID)g_newrawbufi_4311A2, 
        jmpE8buf, sizeof(jmpE8buf));

    // inlinehook decompress
    BYTE callE9buf[0x5]={0xE8}; // call relative
    *(DWORD*)(callE9buf+1) =(DWORD)decompressasb_hook_4311E1-  
        ((DWORD)g_decompressasbi_4311E1 + sizeof(jmpE8buf));
    winhook_patchmemory((LPVOID)g_decompressasbi_4311E1, 
        callE9buf, sizeof(callE9buf));
}

void install_cpbhook()
{
    // inlinehook loadcpb
    BYTE jmpE8buf[0x5]={0xE9}; // jmp relative
    *(DWORD*)(jmpE8buf+1) = (DWORD)loadcpb_hook_419E03-  
        ((DWORD)g_loadcpbi_419E03 + sizeof(jmpE8buf));
    winhook_patchmemory((LPVOID)g_loadcpbi_419E03, 
        jmpE8buf, sizeof(jmpE8buf));

    // inlinehook copycpb24
    *(DWORD*)(jmpE8buf+1) = (DWORD)copycpb24_hook_41E2DB-  
        ((DWORD)g_copycpb24i_41E2DB + sizeof(jmpE8buf));
    winhook_patchmemory((LPVOID)g_copycpb24i_41E2DB, 
        jmpE8buf, sizeof(jmpE8buf));

    // inlinehook copycpb32
    *(DWORD*)(jmpE8buf+1) = (DWORD)copycpb32_hook_41E4C6-  
        ((DWORD)g_copycpb32i_41E4C6 + sizeof(jmpE8buf));
    winhook_patchmemory((LPVOID)g_copycpb32i_41E4C6, 
        jmpE8buf, sizeof(jmpE8buf));

    *(DWORD*)(jmpE8buf+1) = (DWORD)copycpb32_hook_41DEFD-  
        ((DWORD)g_copycpb32i_41DEFD + sizeof(jmpE8buf));
    winhook_patchmemory((LPVOID)g_copycpb32i_41DEFD, 
        jmpE8buf, sizeof(jmpE8buf));
}

void install_mbcheckhook()
{
    /* this hook for splitting multibyte char
    004340F9    | 8A09                  | mov cl,byte ptr ds:[ecx]          | ecx:EntryPoint
    004340FB    | 8AD1                  | mov dl,cl                         |
    004340FD    | 80F2 20               | xor dl,20                         |
    00434100    | 80C2 5F               | add dl,5F                         |
    00434103    | 80FA 3B               | cmp dl,3B                         | check_sjis this is the real place
    00434106    | 0F87 09010000         | ja lamune.434215                  |
    */
    BYTE mbcheckbuf1[] = {0x8A, 0xD1, // mov dl, cl
        0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 
        0x80, 0xFA, 0x80, // cmp dl, 0x80
        0x0F, 0x86, 0x09, 0x01, 0x00, 0x00} ;//jbe lamune.434215
    winhook_patchmemory((LPVOID)0x4340FB,
         mbcheckbuf1, sizeof(mbcheckbuf1));
    
    /* this hook for show multibyte char
    .text:00412EBA
    .text:00412EBA loc_412EBA:
    .text:00412EBA mov     cl, [edi]
    .text:00412EBC mov     al, cl
    .text:00412EBE xor     al, 20h
    .text:00412EC0 add     al, 5Fh ; '_'
    .text:00412EC2 cmp     al, 3Bh ; ';'
    .text:00412EC4 ja      short loc_412EDA
    */
    BYTE mbshowbuf2[] = {0x8A, 0xC1,  //mov cl, [edi]
        0x90, 0x90, 0x90, 0x90, 
        0x3C, 0x80, // cmp al, 0x80
        0x76, 0x14}; // jbe lamune.431210
    winhook_patchmemory((LPVOID)0x412EBC, 
        mbshowbuf2, sizeof(mbshowbuf2));

    /* This hook for fixing \n crash, at 00432FFF
    .text:00432DC1 mov     al, [ebx]
    .text:00432DC3 mov     cl, al
    .text:00432DC5 xor     cl, 20h
    .text:00432DC8 add     cl, 5Fh ; '_'
    .text:00432DCB cmp     cl, 3Bh ; ';'
    .text:00432DCE ja      loc_432ECD
    */
    BYTE mbshowbuf3[] = {0x8A, 0xC8, // mov cl, al
        0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
        0x80, 0xF9, 0x80, // cmp cl, 80
        0x0F, 0x86, 0xF9, 0x00, 0x00, 0x00}; // jbe lamune.432ECD
    winhook_patchmemory((LPVOID)0x432DC3, 
        mbshowbuf3, sizeof(mbshowbuf3));

    /* This hook for log text mbchec
    .text:004339C4 mov     dl, [ecx]
    .text:004339C6 mov     [ebp+78h+var_11], dl
    .text:004339C9 xor     dl, 20h
    .text:004339CC add     dl, 5Fh ; '_'
    .text:004339CF cmp     dl, 3Bh ; ';'
    .text:004339D2 ja      short loc_433A0F
    */

    BYTE mbshowbuf4[] = {
        0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
        0x80, 0xFA, 0x80, // cmp dl, 80
        0x76, 0x3B}; // jbe lamune.433A0F
    winhook_patchmemory((LPVOID)0x4339C9, 
        mbshowbuf4, sizeof(mbshowbuf4));
}

void install_namecheckhook()
{
    /* This hook is for name1 checking
    .text:00421D28 mov     dl, al
    .text:00421D2A add     dl, 5Fh ; '_'
    .text:00421D2D cmp     dl, 3Eh ; '>'
    .text:00421D30 jbe     short loc_421D51
    */
    BYTE namecheckbuf1[] = {0xEB, 0x18}; // jmp lamune.421D42
    winhook_patchmemory((LPVOID)0x421D28, 
        namecheckbuf1, sizeof(namecheckbuf1));

    /* This hook is for name2 checking
    .text:00421D92 mov     dl, al
    .text:00421D94 add     dl, 5Fh ; '_'
    .text:00421D97 cmp     dl, 3Eh ; '>'
    .text:00421D9A jbe     short loc_421DBB
    */
    BYTE namecheckbuf2[] = {0xEB, 0x18}; // jmp lamune.421DAC
    winhook_patchmemory((LPVOID)0x421D92, 
        namecheckbuf2, sizeof(namecheckbuf2));
}

void install_fonthook()
{
    // CreateFontA hook
    if(!winhook_iathook("Gdi32.dll", GetProcAddress(
        GetModuleHandleA("Gdi32.dll"), "CreateFontA"), 
        (PROC)CreateFontA_hook))
    {
        MessageBoxA(0, "CreateFontA hook error", "IAThook error", 0);
    }

    // EnumFontFamiliesExA hook
    if(!winhook_iathook("Gdi32.dll", GetProcAddress(
        GetModuleHandleA("Gdi32.dll"), "EnumFontFamiliesExA"), 
        (PROC)EnumFontFamiliesExA_hook))
    {
        MessageBoxA(0, "EnumFontFamiliesExA hook error", "IAThook error", 0);
    }
}

void install_hooks()
{
    #ifdef _DEBUG
    AllocConsole();
    //MessageBoxA(0, "debug install", "debug", 0);
    freopen("CONOUT$", "w", stdout);
    printf("install hook, v0.2.1, build in 220504 \n");
    #endif
    install_asbhook();
    install_cpbhook();
    install_mbcheckhook();
    install_namecheckhook();
    install_fonthook();
}

BOOL WINAPI DllMain(
    HINSTANCE hinstDLL,  // handle to DLL module
    DWORD fdwReason,     // reason for calling function
    LPVOID lpReserved )  // reserved
{
    switch( fdwReason ) 
    { 
        case DLL_PROCESS_ATTACH:
            install_hooks();
            break;
        case DLL_THREAD_ATTACH:
            break;
        case DLL_THREAD_DETACH:
            break;
        case DLL_PROCESS_DETACH:
            break;
    }
    return TRUE;
}

/*
 *  history
 *  v0.1, decrypted asb import 
 *  v0.1.5 cpb picture dynamic import
 *  v0.2 support the zip archive including outer and inner overlay data
 *  v0.2.1 fix menu_epilogue@n.png not display bug in 0041ddb8
*/