#include <stdio.h>
#include <stdlib.h>
#include <locale.h>
#ifndef NO_REGEX
#include <regex.h>
#endif
#include <sys/stat.h>
#include <io.h>
#include <fcntl.h>
#include "binary_text.h"

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

void free_ftexts(PFTEXTS pftexts)
{
    free(pftexts->black_nodes);
    free(pftexts->white_nodes);
    free(pftexts);
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
    free(pftexts->rawbuf);
    free_ftexts(pftexts);
    
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