/*
    binary_text.h, by devseed
    Some functions of binary_text.py written by C 
    to support embelled game reading this universal binary text format 
    v0.1
*/
#ifndef _BINARY_TEXT_H
#define _BINARY_TEXT_H
typedef struct _FTEXTS_NODE
{
    int num;
    size_t addr;
    size_t size;
    size_t textbufsize;
    char* textbuf;
}FTEXTS_NODE, *PFTEXTS_NODE;

typedef struct _FTEXTS
{
    int white_node_num;
    int black_node_num;
    PFTEXTS_NODE white_nodes; //○ E2 97 8B
    PFTEXTS_NODE black_nodes; //● E2 97 8F
    char* rawbuf;
    size_t rawbufsize; // without \0
}FTEXTS, *PFTEXTS;

// util functions for converting encodings
size_t utf8towchar(wchar_t* dst, char* src, size_t srclen);
size_t sjistowchar(wchar_t* dst, char* src, size_t srclen);
size_t gbktowchar(wchar_t* dst, char* src, size_t srclen);
size_t wchartoutf8(char* dst, wchar_t* src, size_t srclen); // this might be not work
size_t wchartosjis(char* dst, wchar_t* src, size_t srclen); 
size_t wchartogb2312(char* dst, wchar_t* src, size_t srclen);
void printutf8(char* utf8str, size_t utf8strlen);

// some internal functions for ftexts
void count_ftexts(char*buf, size_t bufsize, int *pwhite_node_num, int *pblack_node_num);
FTEXTS_NODE parse_ftexts_line(char* buf, size_t start, size_t end, regex_t* reg);

// printf the inforemations of FTEXTS_NODE for debug
void printf_ftexts_node(PFTEXTS_NODE pnode);

// parse the ftexts into FTEXTS_NODE, use format_text_num first to alloc memories of nodes
PFTEXTS parse_ftexts(char* buf, size_t bufsize); 

// read ftext file and alloc memory of FTEXTS_NODEs
PFTEXTS load_ftexts_file(char* path);

// free each elements of ftexts, without rawbuf
void free_ftexts(PFTEXTS pftexts);

// search the addr exactly in nodes, rerurns the index of nod, if not find return -1
int search_ftexts_address(FTEXTS_NODE nodes[], int node_num, size_t addr); 

#endif