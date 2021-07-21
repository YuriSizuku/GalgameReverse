/*
    binary_text.h, by devseed
    Some functions of binary_text.py written by C 
    to support embelled game reading this universal binary text format 
    v0.1
*/
#ifndef _BINARY_TEXT_H
#define _BINARY_TEXT_H
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