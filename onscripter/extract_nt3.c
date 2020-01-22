#include <stdio.h>
#include <stdlib.h>
int decodeNT3(void *sh, char **buf, unsigned int size, FILE *fp)
{
    int key;
    int tmp;
    int flag;
    char ch;
    char *cur;
    int data_size;

    if(size < 0x920) return -1;
    fseek(fp, 0x91C, 0);
    fread(&key, 4, 1, fp);
    data_size = fread(*buf, 1, size-0x920, fp);
    cur = *buf;
    if(data_size)
    {
        int i=1;
        int flag=1;
        do{
            key ^=  *cur;
            tmp = key + (*cur)*(data_size+1-i) + 0x5D588B65;
            key = tmp;
            *cur^=tmp;
            ch = *cur;
            if(ch=='*')
            {
                if(!flag)
                {
                    i++;
                    cur++;
                    continue;
                }
                else
                {
                    //++*((_DWORD *)this + 120);
                    ch =  *cur;
                }
            }
            if(ch != '\n') //10
            {
                if(!(ch==0x20 || ch== 9)) //SPACE, TAB
                    flag=0;
                i++;
                cur++;
                continue;
            }
            flag = 1;
            i++;
            cur++;
        }
        while (data_size>=i);
    }
    *cur = 10;
    cur++;
    return 0;
}

int extractNT3(char *inpath, char *outpath)
{
    FILE *fp = fopen(inpath, "rb");
    fseek(fp, 0, SEEK_END);
    int size = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    char *buf = malloc(size);
    memset(buf, 0, size);
    int ret = decodeNT3(NULL, &buf, size, fp);
    FILE *fp2 = fopen(outpath, "wb");
    printf("%d", sizeof(buf));
    fwrite(buf, sizeof(char), size, fp2);
    free(buf);
    fclose(fp);
    fclose(fp2);
    return ret;
}

int main(int argc, char **argv)
{
    //FILE* fp = fopen(argv[0], "rb");
    //decodeNT3(NULL,NULL ,0, fp);
    printf("extract onscript.nt3 (by devseed), extract_nt3 input [output]\n");
    char *outpath;
    if(argc<=2)
        outpath = "result.txt";
    else outpath = argv[2];
    int ret = extractNT3(argv[1], outpath);
    if(ret==0) printf("%s extracted successfully!\n", outpath);
    else printf("%s extract faiiled!\n", outpath);
    return 0;
}