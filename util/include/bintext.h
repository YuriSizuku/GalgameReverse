/*
    binary_text.h, by devseed
    Some functions of binary_text.py written by C 
    to support embelled game reading this universal binary text format 
    v0.1
*/
#ifndef _BINTEXT_H
#define _BINTEXT_H
#include <stdint.h>

#ifndef FTEXTS_NODE_EXTRA
#define FTEXTS_NODE_EXTRA
#endif
typedef struct _FTEXTS_NODE
{
    int num;
    size_t addr;
    size_t size;
    size_t textbufsize;
    char* textbuf;
    FTEXTS_NODE_EXTRA
}FTEXTS_NODE, *PFTEXTS_NODE;

#ifndef FTEXTS_EXTRA
#define FTEXTS_EXTRA
#endif
typedef struct _FTEXTS
{
    int white_node_num;
    int black_node_num;
    PFTEXTS_NODE white_nodes; //○ E2 97 8B
    PFTEXTS_NODE black_nodes; //● E2 97 8F
    char* rawbuf;
    size_t rawbufsize; // without \0
    FTEXTS_EXTRA
}FTEXTS, *PFTEXTS;

// double linked list, for index files and FTEXTS
typedef struct _FFILES_NODE FFILES_NODE, *PFFILES_NODE;
#ifndef FFILES_NODE_EXTRA
#define FFILES_NODE_EXTRA // you can extend extra structures here
#endif
#ifndef FFILES_NODE_EXTRA_FREE
#define FFILES_NODE_EXTRA_FREE // for free extra values
#endif
struct _FFILES_NODE
{
    char* path; 
    PFTEXTS pftexts;
    PFFILES_NODE previous;
    PFFILES_NODE next;
    FFILES_NODE_EXTRA
};

// FFILES, FILES with FTEXTS
#ifndef FFILES_EXTRA
#define FFILES_EXTRA
#endif
#ifndef FFILES_EXTRA_FREE
#define FFILES_EXTRA_FREE
#endif
typedef struct _FFILES
{
    int count;
    PFFILES_NODE pstart;
    PFFILES_NODE pend;
    PFFILES_NODE pcur;
    FFILES_EXTRA
}FFILES, *PFFILES;

// util functions for converting encodings
size_t utf8towchar(wchar_t* dst, char* src, size_t maxdstlen);
size_t sjistowchar(wchar_t* dst, char* src, size_t maxdstlen);
size_t gbktowchar(wchar_t* dst, char* src, size_t maxdstlen);
size_t wchartoutf8(char* dst, wchar_t* src, size_t maxdstlen); // this might be not work
size_t wchartosjis(char* dst, wchar_t* src, size_t maxdstlen); 
size_t wchartogb2312(char* dst, wchar_t* src, size_t maxdstlen);
void printutf8(char* utf8str, size_t utf8strlen);

// functions for ftexts
// count how many ftexts in a buf
void count_ftexts(char*buf, size_t bufsize, int *pwhite_node_num, int *pblack_node_num);
// printf the inforemations of FTEXTS_NODE for debug
void printf_ftexts_node(PFTEXTS_NODE pnode);
// parse the ftexts into FTEXTS_NODE, use format_text_num first to alloc memories of nodes
PFTEXTS parse_ftexts(char* buf, size_t bufsize); 
// read ftext file and alloc memory of FTEXTS_NODEs
PFTEXTS load_ftexts_file(char* path);
// search the addr exactly in nodes, rerurns the index of nod, if not find return -1
int search_ftexts_address(FTEXTS_NODE nodes[], int node_num, size_t addr); 
// free each elements of ftexts, without rawbuf
void free_ftexts(PFTEXTS pftexts);

// functions for ftexts files linked-list
PFFILES_NODE search_ffile_path(PFFILES pffiles, char* path);
// after search_ffile, move pcur to the found node
PFFILES_NODE moveto_ffile_path(PFFILES pffiles, char* path);
// insert after pffile_node, if NULL, insert at first, return the count of PFFILES_NODE
int insert_ffile(PFFILES pffiles, PFFILES_NODE pinsert_node, PFFILES_NODE pffile_node); 
int append_ffile(PFFILES pffiles, PFFILES_NODE pffile_node); 
int delete_ffile(PFFILES pffiles, PFFILES_NODE pffile_node);
void free_ffiles_node(PFFILES_NODE pffile_node);
void free_ffiles(PFFILES pffiles);
#endif

#ifdef BINTEXT_IMPLEMENTATION
#include <stdio.h>
#include <stdlib.h>
#include <locale.h>
#ifndef NO_REGEX
#include <regex.h>
#endif
#include <sys/stat.h>

size_t utf8towchar(wchar_t* dst, char* src, size_t maxdstlen)
{
    setlocale(LC_ALL, ".utf-8");
    return mbstowcs(dst, src, maxdstlen);
}

size_t sjistowchar(wchar_t* dst, char* src, size_t maxdstlen)
{
    setlocale(LC_ALL, ".932");
    return mbstowcs(dst, src, maxdstlen);
}

size_t gbktowchar(wchar_t* dst, char* src, size_t maxdstlen)
{
    setlocale(LC_ALL, ".936");
    return mbstowcs(dst, src, maxdstlen);
}

size_t wchartoutf8(char* dst, wchar_t* src, size_t maxdstlen)
{
    setlocale(LC_ALL, ".utf-8");
    return wcstombs(dst, src, maxdstlen);
}

size_t wchartosjis(char* dst, wchar_t* src, size_t maxdstlen)
{
    setlocale(LC_ALL, ".932");
    return wcstombs(dst, src, maxdstlen);
}

size_t wchartogb2312(char* dst, wchar_t* src, size_t maxdstlen)
{
    setlocale(LC_ALL, ".936");
    return wcstombs(dst, src, maxdstlen);
}

void printutf8(char* utf8str, size_t utf8strlen)
{
    wchar_t *tmpwcstr = (wchar_t *)malloc(utf8strlen * 2 * sizeof(wchar_t));
    utf8towchar(tmpwcstr, utf8str, utf8strlen);
    wprintf(L"%ls\n", tmpwcstr);
    free(tmpwcstr);
}

int compare_ftexts_node(const void* p1, const void* p2)
{
    return ((PFTEXTS_NODE)p1)->addr - ((PFTEXTS_NODE)p2)->addr;
}

void count_ftexts(char*buf, size_t bufsize, int *pwhite_node_num, int *pblack_node_num)
{
    int flag_newline = 1;
    for(int i=0;i<bufsize-2;)
    {
       if(flag_newline)
       {
            if(buf[i]=='\n')
            {
                i++;
                continue;
            } 
            if(!strncmp("\xE2\x97\x8B", &buf[i], 3)) // white
            {
                (*pwhite_node_num)++;
                i+=3;
            }
            else if (!strncmp("\xE2\x97\x8F", &buf[i], 3)) // blcak
            {
                (*pblack_node_num)++;
                i+=3;
            }
            else
            {
                i++;
            }
            flag_newline = 0;
       }
       else
       {
           if(buf[i]=='\n') flag_newline=1;
           i++;
       }
    }
}

#ifndef NO_REGEX
FTEXTS_NODE parse_ftexts_line(char* buf, size_t start, size_t end, regex_t* reg)
{
    char tmpbuf[2048];
    regmatch_t m[5];
    FTEXTS_NODE node = {0};

    strncpy(tmpbuf, &buf[start], end-start);
    tmpbuf[end-start]='\0';
    int ret =regexec(reg, tmpbuf, 5, m, REG_NOTBOL);
    if(!ret)
    {
        tmpbuf[m[1].rm_eo] = '\0';
        node.num =atoi(tmpbuf+m[1].rm_so);
        tmpbuf[m[2].rm_eo] = '\0';
        node.addr = strtol(tmpbuf+m[2].rm_so, NULL, 16);
        tmpbuf[m[3].rm_eo] = '\0';
        node.size = strtol(tmpbuf+m[3].rm_so, NULL, 16);
        node.textbuf = buf + start + m[4].rm_so;
        node.textbufsize = (size_t)(m[4].rm_eo - m[4].rm_so);
        //printf_ftexts_node(&node);
    }
    else
    {
        regerror(ret, reg, tmpbuf, 256);
        printf("error(%s, %d): white_reg  %s\n", __FILE__, __LINE__, tmpbuf);
    }
    return node;
}
#else
FTEXTS_NODE parse_ftexts_line(char* buf, size_t start, size_t end)
{
    char tmpbuf[2048];
    FTEXTS_NODE node = {0};
    strncpy(tmpbuf, &buf[start], end-start);
    size_t i=3;
    size_t strstart=i;
    
    while(tmpbuf[i]!='|') 
    {
        if(i>end-start-3) return node;
        i++;
    }
    tmpbuf[i++]=0;
    node.num =atoi(tmpbuf+strstart);
    strstart = i;
    
    while(tmpbuf[i]!='|') i++;
    {
        if(i>end-start-3) return node;
        i++;
    }
    tmpbuf[i++]=0;
    node.addr = strtol(tmpbuf+strstart, NULL, 16);
    strstart = i;

    while(tmpbuf[i]!='\xe2')
    {
        if(i>end-start-3) return node;
        i++; 
    }
    tmpbuf[i]=0;
    node.size = strtol(tmpbuf+strstart, NULL, 16);
    node.textbuf = buf + start + i + 4; // a space is after black or white point
    node.textbufsize = (size_t)(end - (start + i + 4));
    //printf_ftexts_node(&node);
    return node;
}
#endif

void printf_ftexts_node(PFTEXTS_NODE pnode)
{
    printf("num=%d, addr=%x, size=%x, textbufsize=%x, ", 
            pnode->num, pnode->addr, pnode->size, pnode->textbufsize);
    printutf8(pnode->textbuf, pnode->textbufsize);
}

PFTEXTS parse_ftexts(char* buf, size_t bufsize)
{
    PFTEXTS pftexts = malloc(sizeof(FTEXTS));
    memset(pftexts, 0, sizeof(FTEXTS));
    pftexts->rawbuf = buf;
    pftexts->rawbufsize = bufsize;

    // count node number, and alloc memory
    count_ftexts(buf, bufsize, &pftexts->white_node_num, &pftexts->black_node_num);
    pftexts->black_nodes = calloc(pftexts->black_node_num, sizeof(FTEXTS_NODE));
    pftexts->white_nodes = calloc(pftexts->white_node_num, sizeof(FTEXTS_NODE));

    // paser every node
    int white_idx=0, black_idx=0;
    FTEXTS_NODE tmpnode;

#ifndef NO_REGEX
    regex_t  white_reg, black_reg;
    regcomp(&white_reg, "\\xE2\\x97\\x8B(\\d*)\\|(.*)\\|(.*)\\xE2\\x97\\x8B[ ](.*)", REG_EXTENDED);
    regcomp(&black_reg, "\\xE2\\x97\\x8F(\\d*)\\|(.*)\\|(.*)\\xE2\\x97\\x8F[ ](.*)", REG_EXTENDED);
#endif
    for(int i=0;i<bufsize-2;)
    {
        size_t start = i;
        while(buf[i]!='\n'&&i<bufsize) i++;

        if(!strncmp("\xE2\x97\x8B", &buf[start], 3)) // white
        {
#ifndef NO_REGEX
            tmpnode = parse_ftexts_line(buf, start, i, &white_reg);
#else
            tmpnode = parse_ftexts_line(buf, start, i);
#endif
            if(tmpnode.textbufsize > 0) pftexts->white_nodes[white_idx++] = tmpnode;
        }
        else if (!strncmp("\xE2\x97\x8F", &buf[start], 3)) // blcak
        {
#ifndef NO_REGEX
            tmpnode = parse_ftexts_line(buf, start, i, &black_reg);
#else
            tmpnode = parse_ftexts_line(buf, start, i);
#endif
            if(tmpnode.textbufsize > 0) pftexts->black_nodes[black_idx++] = tmpnode;
        }
       i++;
    }
    qsort(pftexts->white_nodes, pftexts->white_node_num, sizeof(FTEXTS_NODE), compare_ftexts_node);
    qsort(pftexts->black_nodes, pftexts->black_node_num, sizeof(FTEXTS_NODE), compare_ftexts_node);
#ifndef NO_REGEX
    regfree(&black_reg);
    regfree(&white_reg);
#endif
    return pftexts;
}

PFTEXTS load_ftexts_file(char* path)
{
    struct stat st;
    stat(path, &st);
    size_t bufsize = st.st_size;
    if(bufsize<3)
    {
        printf("error(in %s, %d): file is too short", __FILE__, __LINE__);
        return 0;
    }

    char* buf = (char*)malloc(bufsize);
    FILE* fp=fopen(path, "r");
    fread(buf, 1, bufsize, fp);
    fclose(fp);

    PFTEXTS pftexts = parse_ftexts(buf, bufsize);
    return pftexts;
}

int search_ftexts_address(FTEXTS_NODE nodes[], int node_num, size_t addr)
{
    int start=0, end=node_num-1;
    if(nodes==NULL || end<0) return -1;
    while(end-start>1)
    {
        int cur = (start+end)/2;
        if(nodes[cur].addr==addr) return cur;
        else if(nodes[cur].addr<addr) start=cur;
        else end=cur;
    }
    if(nodes[start].addr==addr) return start;
    else if (nodes[end].addr==addr) return end;
    else return -1;
}

void free_ftexts(PFTEXTS pftexts)
{
    free(pftexts->black_nodes);
    free(pftexts->white_nodes);
    free(pftexts->rawbuf);
    free(pftexts);
}

PFFILES_NODE search_ffile_path(PFFILES pffiles, char* path)
{
    if(!pffiles || !pffiles->pstart) return NULL;
    PFFILES_NODE ptarget = pffiles->pstart;
    while (ptarget)
    {
        if(!strcmp(ptarget->path, path)) return  ptarget;
        ptarget = ptarget->next;
    }
    return NULL;
}

PFFILES_NODE moveto_ffile_path(PFFILES pffiles, char* path)
{
    PFFILES_NODE ptarget = search_ffile_path(pffiles, path);
    if(!ptarget) pffiles->pcur = ptarget;
    return ptarget;
}

int insert_ffile(PFFILES pffiles, PFFILES_NODE pinsert_node, PFFILES_NODE pffile_node)
{
    if(!pffile_node || !pffiles) return -1;
    if(!pinsert_node) // insert at first
    {
        if(!pffiles->pstart) // if empty linked-list
        {
            pffiles->pstart = pffiles->pend = pffiles->pcur = pffile_node;
        }
        else
        {
            pffiles->pstart->previous = pffile_node;
            pffile_node->previous = NULL;
            pffile_node->next = pffiles->pstart;
            pffiles->pstart = pffile_node;
        }
        return ++pffiles->count;
    }
    else
    {
        pffile_node->previous = pinsert_node;
        pffile_node->next = pinsert_node->next;
        pffile_node->previous->next = pffile_node;
        if(!pffile_node->next) pffiles->pend = pffile_node;
        return ++pffiles->count;
    }
}

int append_ffile(PFFILES pffiles, PFFILES_NODE pffile_node)
{
    if(!pffiles) return -1;
    return insert_ffile(pffiles, pffiles->pend, pffile_node);
}

int delete_ffile(PFFILES pffiles, PFFILES_NODE pffile_node)
{
    if(!pffiles) return -1;
    if(pffiles->pcur == pffile_node) pffiles->pcur = NULL;
    if(!pffile_node->previous) // delete first
    {
        pffiles->pstart = pffile_node->next;
        if(pffiles->pstart) pffiles->pstart->previous = NULL;
        free_ffiles_node(pffile_node);
        return --pffiles->count;
    }
    else
    {
        pffile_node->previous->next = pffile_node->next;
        if(!pffile_node->next) pffiles->pend = pffile_node->previous;
        free_ffiles_node(pffile_node);
        return --pffiles->count;
    }
}

void free_ffiles_node(PFFILES_NODE pffile_node)
{
    if(!pffile_node) return;
    free(pffile_node->path);
    free_ftexts(pffile_node->pftexts);
    FFILES_NODE_EXTRA_FREE
    free(pffile_node);
}

void free_ffiles(PFFILES pffiles)
{
    if(!pffiles) return;
    if(pffiles->pstart)
    {
        PFFILES_NODE pcur = pffiles->pstart;
        while (pcur)
        {
            PFFILES_NODE ptmp = pcur;
            pcur = pcur->next;
            free_ffiles_node(ptmp);
        }
    }
    FFILES_EXTRA_FREE
    free(pffiles);
}

#ifdef _TEST_BINARY_TEXT
int main(int argc, char **argv)
{
    // test ftexts
    PFTEXTS pftexts = load_ftexts_file(argv[1]);
    printf("pftexts rawbufsize=0x%x, white_node_num=%d, black_node_num=%d\n", 
        pftexts->rawbufsize, pftexts->white_node_num, pftexts->black_node_num);
    size_t addr = 0x81de;
    int idx = search_ftexts_address(pftexts->white_nodes, pftexts->white_node_num, addr);
    printf("search at %x, return %d\n", addr, idx);
    printf_ftexts_node(&pftexts->white_nodes[idx]);

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
    pfile_node2->pftexts =  load_ftexts_file(argv[2]);
    append_ffile(pfiles, pfile_node);
    insert_ffile(pfiles, pfiles->pstart, pfile_node2);
    delete_ffile(pfiles, pfiles->pstart);
    PFFILES_NODE ptmp = search_ffile_path(pfiles, "a02.mjo.txt");
    if(ptmp) printf("fuound ffile %x, %s\n", ptmp, ptmp->path);
    free_ffiles(pfiles);
    
    // test converter
    wchar_t wcstr[100]=L"测试";
    unsigned char mcstr[100] = {0};
    size_t ret = wchartogb2312(mcstr, wcstr, wcslen(wcstr));
    printf("%x %x -> %d %02x %02x %02x %02x\n", wcstr[0], wcstr[1], 
        ret, mcstr[0], mcstr[1], mcstr[2], mcstr[3]);
    printutf8("\xE2\x97\x8F\xE2\x97\x8B", 6); // ●○
    return 0;
}
#endif
#endif