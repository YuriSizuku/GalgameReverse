/*
build the ConvertGb2312ToUtf16 arm64 binray code to support gb2312
	v0.1, developed by devseed
*/

#include <stddef.h>
#include <stdint.h>
#ifdef _DEBUG
#include <stdio.h>
#endif 

#define FONTMAP_ADDR 0x710014AE98
#define FONTMAP_OFFSET_TO_LR (FONTMAP_ADDR-0x710000CB04)

int ConvertUtf16ToUtf16(uint16_t* unicode_buf, int unicode_bufsize, const unsigned char* multibye_buf) //this not be worked, becuase script asci
{
    int i=0;
    while(multibye_buf[i] || multibye_buf[i+1])
    {
        if(i>unicode_bufsize) return 1;
        unicode_buf[i/2] = multibye_buf[i] + (multibye_buf[i+1]<<8&0xff00); 
        i +=2;
    }
    return 0;
}

int ConvertGb2312ToUtf16(uint16_t* unicode_buf, int unicode_bufsize, const unsigned char* multibye_buf)
{
    int unicode_idx = 0;
    int multibyte_idx = 0;
    register uint16_t* fontmap = 0;
    // because only one position invoke this function, can use LR
    __asm__  __volatile__ ("mov %0, lr;" : "=r"(fontmap));
    fontmap = (uint16_t*)((uint64_t)fontmap + FONTMAP_OFFSET_TO_LR);

    while(multibye_buf[multibyte_idx])
    {
        if(unicode_idx>unicode_bufsize) return 1;
        if(multibye_buf[multibyte_idx] < 0x7f) // 1byte asci
        {
            unicode_buf[unicode_idx++] = multibye_buf[multibyte_idx++];
            continue;
        }

        unsigned char first_byte = multibye_buf[multibyte_idx++];
        if(first_byte>=0xa1 && first_byte<=0xfe)
        {
            unsigned char second_byte = multibye_buf[multibyte_idx++];
            if(second_byte>=0xa1 && second_byte<=0xfe)
            {
                // fontmap is big-endian
                unicode_buf[unicode_idx++] = fontmap[(second_byte-0xa1)+(first_byte-0xa1)*(0xff-0xa1)];
            }
            else 
            {
                multibyte_idx+=2;
                unicode_buf[unicode_idx++] =  fontmap[1];
                //return 2;
            }
        }
        else
        {
            multibyte_idx+=2;
            unicode_buf[unicode_idx++] =  fontmap[1];
            //return 2;
        }
    }
    return 0;
}

int FONT_IsJIS(unsigned char a1) // seems not used
{
    if(a1>=0x81 && a1<=0xfe) return 1;
    else return 0;
}

int ReadNextCharSjis(void* this) // seems not used
{
    unsigned char *pcur = (unsigned char *)this;
    int result=0;
    if(*pcur<0x80)
    {
        result = *pcur;
        pcur += 1;
    }
    else
    {
         result = ((*pcur<<8)&0xff00)+*(pcur+1);
         pcur += 2;
    }
    return result;
}

#ifdef _DEBUG
int main(int argc, char** argv)
{
    char *str = "\x4b\x6d\xd5\x8b";
    wchar_t wstr[100] = {0};
    ConvertUtf16ToUtf16(wstr, 4, str);
    wprintf(L"%ls\n", wstr);
    return 0;
}
#endif