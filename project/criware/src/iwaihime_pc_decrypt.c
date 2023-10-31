#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef unsigned int DWORD;
typedef unsigned char BYTE;

size_t decrypt_asm(BYTE* dst, BYTE *src, size_t src_size) //445f40, dst=eax, src=ecx
{
    BYTE *buf=(BYTE*)malloc(3*src_size); //6975F28                
    BYTE *edi = src;
    BYTE *esi = dst;
    DWORD t1, t2, t3; //[ebp-4], [ebp-8], [ebp-c]
    DWORD eax, ebx, ecx, edx;

    ebx = *(DWORD*)edi + (DWORD)esi; //edge
    t2 = ebx;
    edi += 4;
    
    memset(buf, 0, 0xFEE);
    eax = 0XFEE;
    edx = 0;
    while(1)
    {
        edx >>= 1;
        t1 = edx;
        if (!(edx & 0x100)) // 00 01
        {
            edx = *edi;
            edi++;
            edx |= 0xff00;
            t1 = edx;
        }
        ecx = *edi;
        if ((BYTE)edx & 1)
        {
            buf[eax] = (BYTE)ecx;
            eax++;
            *esi = (BYTE)ecx;
            esi++;
            edi++;
            eax &= 0xFFF;
            if(esi >= ebx) 
            {
                free(buf);
                return (size_t)(ebx-(DWORD)dst);    
            }
        }
        else
        {
            edx = *(edi+1);
            ebx = (edx & 0XF0)<<4;
            ecx |= ebx;
            edx &= 0xF;
            ebx = edx+ecx+2;
            edi += 2;
            t3 = ebx;
            ebx = t2;
            edx = ecx;
            if(ecx>ebx)
            {
                edx = t1;
                continue;
            }
            do{
                ecx = edx & 0xFFF;
                ecx = buf[ecx];
                buf[eax] = (BYTE) ecx;
                eax ++;
                (*esi) = (BYTE) ecx;
                esi++;
                eax &= 0XFFF;
                if(esi >= ebx) 
                {
                    free(buf);
                    return (size_t)(ebx-(DWORD)dst);
                }
                edx++;
            } while (edx<=t3);
            edx = t1;
        }
    }
}

size_t decrypt(BYTE* dst, BYTE *src, size_t src_size) //LZSS 
{
    BYTE *buf=(BYTE*)malloc(0x1000);               
    BYTE *cur_src = src;
    BYTE *cur_dst = dst;
    BYTE *end_dst =  (DWORD)cur_dst + *(DWORD*)cur_src;
    DWORD idx_buff, i, last, c1, c2;

    cur_src += 4;
    memset(buf, 0, 0xFEE);
    idx_buff = 0XFEE;

    c1 = 0; //index byte
    while(1)
    {
        c1 >>= 1;
        if (!(c1 & 0x100)) // c1 bit[9] is 0, it means do 8 times
        {
            c1 = *cur_src;
            c1 |= 0xff00; //make a mark, and to 16bit
            cur_src++;
        }
        if ((BYTE)c1 & 0x1) //copy to buf directly
        {
            buf[idx_buff] = *cur_src;
            *cur_dst = *cur_src;
            idx_buff++;
            idx_buff &= 0xFFF; //cicle buffer
            cur_dst++;
            cur_src++;
            if(cur_dst >= end_dst) 
            {
                free(buf);
                return (size_t)((BYTE*)end_dst - dst);    
            }
        }
        else
        {
            c2 = *(cur_src+1); //index byte2
            i = *cur_src | ((c2 & 0XF0)<<4); //use c1 and c2 (higher 4bits) to determine index
            last = (c2 & 0xf) + i +2; // length = c2 lower 4bit, 2 without length 2 chars
            cur_src += 2; //c1, c2 two index byte

            if(i > end_dst)
            {
                continue;
            }
            do
            {
                buf[idx_buff] = buf[i & 0xFFF];
                *cur_dst = buf[i & 0xFFF];
                idx_buff++;
                idx_buff &= 0xFFF;
                cur_dst++;
                if(cur_dst >= end_dst) 
                {
                    free(buf);
                    return (size_t)((BYTE*)end_dst - dst);  
                }
                i++;
            } while (i <= last);
        }
    }
}

size_t encrypt(BYTE* dst, BYTE *src, size_t src_size) 
//remove the first 0x4 bytes, use lzss to “encrypt”
{
    return 0;
} 


int main(int argc, char *argvs[])
{
    char inpath[256];
    char outpath[256];
    
    if (argc==1) 
    {
        printf("iwaihime_pc_decrypt.exe inpath [outpath]");
        return -1;
    }
    else if(argc==2) strcpy(outpath, "out.bin");
    else strcpy(outpath, argvs[2]);
    strcpy(inpath, argvs[1]);
    
    FILE *fp = fopen(inpath, "rb");
    if(!fp) 
    {
        printf("File %s open failed!\n", inpath);
        return -1;
    }
    fseek(fp, 0L, SEEK_END);
    size_t fsize = ftell(fp);
   
    fseek(fp, 0L, SEEK_SET);
    BYTE *src = malloc(fsize);
    BYTE *dst = malloc(3*fsize);   
    fread(src, 1, fsize, fp);
    memcpy(dst, src, fsize);
    //size_t dst_size = decrypt_asm(dst, src, fsize);
    size_t dst_size = decrypt(dst, src, fsize);

    FILE *fp2 = fopen(outpath, "wb");
    if(!fp2) 
    {
        printf("File %s open failed!\n", outpath);
        return -1;
    }
    fwrite(dst, 1, dst_size, fp2);
    
    free(dst);
    free(src);
    fclose(fp);
    fclose(fp2);
}