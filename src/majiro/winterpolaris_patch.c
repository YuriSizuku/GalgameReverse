/*
  A experiment for dynamic chs with majiro V3, 
  by devseed, v0.1
*/

#include<Windows.h>
#include<stdio.h>
#define BINTEXT_IMPLEMENTATION
#include "bintext.h"
#define WINHOOK_IMPLEMENTATION
#include "winhook.h"

typedef struct _MJO_NODE MJO_NODE, *PMJO_NODE;
struct _MJO_NODE
{
    char mjo_name[256];
    PFTEXTS text_index;
    PMJO_NODE previous;
    PMJO_NODE next; // end with next=NULL
};

#define MJO_TEXT_DIR "./mjotext/"
void* g_base = (void*)0x400000; // app base addr
void* g_showtext = (void*)0x442760; // replaced text buffer
PMJO_NODE g_mjos=NULL, g_cur_mjo=NULL; // pointer to index structure
char g_textbuf[2048] = {0}; // for showing replaced text

__declspec(dllexport) void dummy()
{

}

// try load mjo decrypt text from file, result to g_cur_mjo
void load_mjo_ftexts(char* mjo_name)
{
    char path[256]=MJO_TEXT_DIR;
    strcat(path, mjo_name);
    strcat(path, ".txt");
    FILE *fp=fopen(path, "r");
    if(fp)
    {
        fclose(fp);
        printf("load_mjo_ftexts, %s found!\n", path);
        g_cur_mjo->text_index = bintext_load_ftextsfile(path);
        strcpy(g_cur_mjo->mjo_name, mjo_name);
    }
    else
    {
        printf("load_mjo_ftexts, %s not found!\n", path);
    }
}

// serarch if already load the mjo decrypt texts, g_cur_mjo will move to the target mjo node
void __stdcall search_mjo_ftexts(char* mjo_name)
{
    printf("%s\n", mjo_name);
    if(g_mjos==NULL)
    {
        printf("search_mjo_ftexts, creating MJO_NODE with %s...\n", mjo_name);
        g_mjos = malloc(sizeof(MJO_NODE));
        memset(g_mjos, 0, sizeof(MJO_NODE));
        g_cur_mjo = g_mjos;
        load_mjo_ftexts(mjo_name);
    }
    else if(strcmp(mjo_name, g_cur_mjo->mjo_name)) // cur mjo_node not target mjo
    {
        g_cur_mjo = g_mjos; // to search from first
        while (g_cur_mjo->next) // serach for already loaded node
        {
            if(!strcmp(g_cur_mjo->mjo_name, mjo_name)) 
            {
                printf("search_mjo_ftexts, %s is in the list at %lx\n", mjo_name, (unsigned long)g_cur_mjo);
                return;
            }
            g_cur_mjo = g_cur_mjo->next;
        }
        if(!strcmp(g_cur_mjo->mjo_name, mjo_name)) // last
        {
            printf("search_mjo_ftexts, %s is in the list at %lx\n", mjo_name, (unsigned long)g_cur_mjo);
            return;
        }
        if(g_cur_mjo->text_index!=NULL) // add new node
        {
            printf("search_mjo_ftexts, %s not in the list, trying to load...\n", mjo_name);
            PMJO_NODE tmp_mjo_node = malloc(sizeof(MJO_NODE));
            memset(tmp_mjo_node, 0, sizeof(MJO_NODE));
            tmp_mjo_node->previous = g_cur_mjo;
            g_cur_mjo->next = tmp_mjo_node;
            g_cur_mjo = g_cur_mjo->next;
            load_mjo_ftexts(mjo_name);
        }
    }
}

// find target chs text and write to g_textbuf
void __stdcall find_mjo_chstext(size_t addr) 
{
    wchar_t wcharbuf[1024];
    PFTEXTS pnode=g_cur_mjo->text_index;
    printf("find_mjo_chstext(%x), ", addr);
    if(!pnode) 
    {
        printf("pnode is empty!\n");
        return;
    }
    int idx = bintext_search_ftextsaddr(pnode->black_nodes, pnode->black_node_num, addr);
    if(idx!=-1)
    {
        char* blackbuf = pnode->black_nodes[idx].textbuf;
        size_t blackbufsize = pnode->black_nodes[idx].textbufsize;
        int idx_white = idx;
        strncpy(g_textbuf, blackbuf,blackbufsize);
        g_textbuf[blackbufsize]='\0';

        // filter of no need to convert text (not needed in this game)
        if(idx >= pnode->white_node_num || 
            pnode->white_nodes[idx_white].addr!=pnode->black_nodes[idx_white].addr)
        {
            idx_white = bintext_search_ftextsaddr(pnode->black_nodes, pnode->black_node_num, addr);
        }
        if(idx_white!=-1)
        {
            char* whitebuf = pnode->white_nodes[idx_white].textbuf;
            size_t whitebufsize = pnode->white_nodes[idx_white].textbufsize;
            if (!strcmp(g_textbuf, "主人公"))
            {
                g_textbuf[0] = '\0';
                return;
            }
            if (!strcmp(g_textbuf, "ツバキ"))
            {
                g_textbuf[0] = '\0';
                return;
            }
        }

        // convert utf8 ftexts to gb2312
        size_t size = bintext_utf8towchar(wcharbuf, g_textbuf, blackbufsize);
        size = bintext_wchartogb2312(g_textbuf, wcharbuf, blackbufsize);
        if(size>sizeof(g_textbuf)) size=0; //if size=-1 when error occured, for example '−' is not allowed
        g_textbuf[size] = '\0';
        printf("blackbufsize=%x, g_textbuf_size=%x,%s\n",  blackbufsize, size, g_textbuf);
    }
    else
    {
        printf("not found!\n");
        g_textbuf[0] = '\0';
    }
}

HFONT WINAPI CreateFontIndirectA_hook(LOGFONTA *lplf)
{
    lplf->lfCharSet = GB2312_CHARSET;
    lplf->lfHeight+=2; // for showing '「 ', the default height is not enough
    strcpy(lplf->lfFaceName , "simhei");
    return CreateFontIndirectA(lplf);
}

// only hook TextOutA not worked, because the distance of moving next
BOOL WINAPI TextOutA_hook(HDC hdc, int x, int y, LPCSTR lpString, int c) 
{
    if((unsigned char)(*lpString)>0x80) c=2;
    return TextOutA(hdc, x, y, lpString, c);
}

HWND WINAPI CreateWindowExA_hook(
  DWORD     dwExStyle,
  LPCSTR    lpClassName,
  LPCSTR    lpWindowName,
  DWORD     dwStyle,
  int       X,
  int       Y,
  int       nWidth,
  int       nHeight,
  HWND      hWndParent,
  HMENU     hMenu,
  HINSTANCE hInstance,
  LPVOID    lpParam
)
{
    // because this src code is utf-8, can not directly use
    strcpy((char*)lpWindowName, "WinterPolars \xb6\xaf\xcc\xac\xba\xba\xbb\xaf\xb2\xe2\xca\xd4"); 
    return CreateWindowExA(dwExStyle, lpClassName, lpWindowName, dwStyle, X, Y, nWidth, nHeight, hWndParent, hMenu, hInstance, lpParam);
}

__declspec(naked) void showtext_hook() // replace text to chs, inline hook code
{
    __asm{
        pushad        
        mov ecx, g_base
        add ecx, 0xdc350 
        mov ecx, dword ptr ds:[ecx] ;mjo struct
        push ecx ;because the function might change the register
        push ecx ;mjo_name, actually this is the last load mjo_name, not current mjo_name
        call search_mjo_ftexts
        pop ecx ;restore ecx for mjo struct
        lea eax, [ecx+29h*4]
        mov eax, dword ptr ds:[eax] ;mjo_addr_base
        mov ebx, g_base
        add ebx, 5D1A58h - 400000h
        mov ebx, dword ptr ds:[ebx]
        mov ebx, dword ptr ds:[ebx] ;mjo_addr_cur
        
        inc ebx
        loop1: ; do while
        dec ebx
        cmp byte ptr[ebx], 0
        jne loop1
        
        loop2:
        dec ebx
        cmp byte ptr[ebx], 0
        jne loop2
        inc ebx

        sub ebx, eax
        push ebx
        call find_mjo_chstext
        lea esi, g_textbuf
        cmp byte ptr [esi], 0 ; if g_textbuf is empty, just use origin buffer
        je leave
        mov edi, g_base
        add edi, 52CCE4h - 400000h
        mov edi, dword ptr ds:[edi] ;text_addr
        
        replace_text:
        mov al, byte ptr [esi]
        mov byte ptr [edi], al
        test al, al
        jz leave
        inc esi
        inc edi
        jmp replace_text
        
        leave:
        popad
        jmp dword ptr ds:[g_showtext]
    }
}

__declspec(naked) void is_twobyte() // cdecl
{
    __asm
    {
        mov eax, [esp+0x4]
        movzx eax, al
        cmp eax, 0x80
        ja twobyte
        xor eax, eax
        ret
        twobyte:
        mov eax, 1
        ret
    }
}

void install_font_hook()
{
    if(!winhook_iathook("Gdi32.dll", (PROC)CreateFontIndirectA, (PROC)CreateFontIndirectA_hook))
    {
        MessageBoxA(NULL, "CreateFontIndirectA iat hook failed!", "error", 0);
    }

    if(!winhook_iathook("User32.dll", (PROC)CreateWindowExA, (PROC)CreateWindowExA_hook))
    {
        MessageBoxA(NULL, "CreateWindowExA iat hook failed!", "error", 0);
    }
}

void install_text_hook()
{
    // inline hook for replace text
    PVOID pfnOlds[3] = {g_base+0x42820, g_base+0x7EE00, NULL};
    PVOID pfnNews[3] = {showtext_hook, is_twobyte, NULL};
    printf("Before inline hooks\n");
    for(int i=0;i<sizeof(pfnOlds)/sizeof(PVOID)-1;i++)
    {
        printf("%d, %lx -> %lx\n", i, (unsigned long)pfnOlds[i], (unsigned long)pfnNews[i]); 
    }
    winhook_inlinehooks(pfnOlds, pfnNews);
    g_showtext = pfnOlds[0];
    printf("After inline hooks\n");
    for(int i=0;i<sizeof(pfnOlds)/sizeof(PVOID)-1;i++)
    {
        printf("%d, %lx -> %lx\n", i, (unsigned long)pfnOlds[i], (unsigned long)pfnNews[i]); 
    }
}

void install_hooks()
{
    g_base = (void*)GetModuleHandleA(NULL);
#ifdef _DEBUG
    winhook_installconsole();
    // MessageBoxA(NULL, "winterpolar_hook start", "install_hook", 0);
#endif
    install_font_hook();
    install_text_hook();
}

#ifdef _TEST_BINARY_TEXT
int main(int argc, char **argv)
{
    // test ftexts
    PFTEXTS pftexts = bintext_load_ftextsfile(argv[1]);
    printf("pftexts rawbufsize=0x%x, white_node_num=%d, black_node_num=%d\n", 
        pftexts->rawbufsize, pftexts->white_node_num, pftexts->black_node_num);
    size_t addr = 0x81de;
    int idx = bintext_search_ftextsaddr(pftexts->white_nodes, pftexts->white_node_num, addr);
    printf("search at %x, return %d\n", addr, idx);
    bintext_print_ftextnode(&pftexts->white_nodes[idx]);

    // test ffiles
    PFFILES pfiles = (PFFILES)malloc(sizeof(FFILES));
    PFFILES_NODE pfile_node = (PFFILES_NODE)malloc(sizeof(FFILES_NODE));
    PFFILES_NODE pfile_node2 = (PFFILES_NODE)malloc(sizeof(FFILES_NODE));
    memset(pfiles, 0, sizeof(FFILES));
    memset(pfile_node, 0, sizeof(FFILES_NODE));
    memset(pfile_node2, 0, sizeof(FFILES_NODE));
    char* path=(char*)malloc(strlen(argv[1]));
    strcpy(path, argv[1]);
    pfile_node->path = path;
    pfile_node->pftexts = pftexts;
    path =(char*)malloc(strlen(argv[2]));
    strcpy(path, argv[2]);
    pfile_node2->path = path;
    pfile_node2->pftexts =  bintext_load_ftextsfile(argv[2]);
    bintext_append_ffilenode(pfiles, pfile_node);
    bintext_insert_ffilenode(pfiles, pfiles->pstart, pfile_node2);
    bintext_delete_ffilenode(pfiles, pfiles->pstart);
    PFFILES_NODE ptmp = bintext_search_ffile(pfiles, "a02.mjo.txt");
    if(ptmp) printf("fuound ffile %x, %s\n", ptmp, ptmp->path);
    bintext_free_ffiles(pfiles);
    
    // test converter
    wchar_t wcstr[100]=L"测试";
    unsigned char mcstr[100] = {0};
    size_t ret = bintext_wchartogb2312(mcstr, wcstr, wcslen(wcstr));
    printf("%x %x -> %d %02x %02x %02x %02x\n", wcstr[0], wcstr[1], 
        ret, mcstr[0], mcstr[1], mcstr[2], mcstr[3]);
    bintext_printutf8("\xE2\x97\x8F\xE2\x97\x8B", 6); // ●○
    return 0;
}
#else
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
#endif