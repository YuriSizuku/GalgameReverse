/**
 * common macro define
 *   v0.1.1, developed by devseed
*/

#ifndef _COMMDEF_H
#define _COMMDEF_H
#define COMMDEF_VERSION "0.1.1"
#ifdef __cplusplus
extern "C" {
#endif
#include <stdio.h>
#include <stdint.h>

// function declear macro
#if defined(_MSC_VER) || defined(__TINYC__)
#ifndef STDCALL
#define STDCALL __stdcall
#endif
#ifndef NAKED
#define NAKED __declspec(naked)
#endif
#ifndef INLINE
#define INLINE __forceinline
#endif
#ifndef NOINLINE
#define NOINLINE __declspec(noinline)
#endif
#ifndef EXPORT
#define EXPORT __declspec(dllexport)
#endif
#else
#ifndef STDCALL
#define STDCALL __attribute__((stdcall))
#endif
#ifndef NAKED
#define NAKED __attribute__((naked))
#endif
#ifndef INLINE
#define INLINE __attribute__((always_inline)) inline
#endif
#ifndef NOINLINE
#define NOINLINE __attribute__((noinline))
#endif
#ifndef EXPORT 
#define EXPORT __attribute__((visibility("default")))
#endif
#endif // _MSC_VER
#if defined(__TINYC__) // fix tcc not support inline
#ifdef INLINE
#undef INLINE
#endif
#define INLINE
#endif // __TINYC__
#ifndef IN
#define IN
#endif // IN
#ifndef OUT
#define OUT
#endif // OUT
#ifndef OPTIONAL
#define OPTIONAL
#endif // OPTIONAL

// log macro
#ifndef LOG_LEVEL_
#define LOG_LEVEL_
#define LOG_LEVEL_ERROR 1
#define LOG_LEVEL_WARNING 2
#define LOG_LEVEL_INFO 3
#define LOG_LEVEL_DEBUG 4
#define LOG_LEVEL_VERBOSE 5
#define LogTagPrintf(format, tag, ...) {\
    printf("[%s,%s] ", __func__, tag);\
    printf(format, ##__VA_ARGS__);}
#define LogTagWprintf(format, tag, ...) {\
    printf("[%s,%s] ", __func__, tag);\
    wprintf(format, ##__VA_ARGS__);}
#define DummyPrintf(format, ...)
#define LOG(format, ...) LogTagPrintf(format, "I", ##__VA_ARGS__)
#define LOGL(format, ...) LogTagWprintf(format, "I", ##__VA_ARGS__)
#define LOGe(format, ...) LogTagPrintf(format, "E", ##__VA_ARGS__)
#define LOGLe(format, ...) LogTagWprintf(format, "E", ##__VA_ARGS__)
#define LOGw(format, ...) LogTagPrintf(format, "W", ##__VA_ARGS__)
#define LOGLw(format, ...) LogTagWprintf(format, "W", ##__VA_ARGS__)
#define LOGi(format, ...) LogTagPrintf(format, "I", ##__VA_ARGS__)
#define LOGLi(format, ...) LogTagWprintf(format, "I", ##__VA_ARGS__)
#define LOGd(format, ...) LogTagPrintf(format, "D", ##__VA_ARGS__)
#define LOGLd(format, ...) LogTagWprintf(format, "D", ##__VA_ARGS__)
#define LOGv(format, ...) LogTagPrintf(format, "V", ##__VA_ARGS__)
#define LOGLv(format, ...) LogTagWprintf(format, "V", ##__VA_ARGS__)
#endif // LOG_LEVEL_
#ifndef LOG_LEVEL
#define LOG_LEVEL LOG_LEVEL_INFO
#endif // LOG_LEVEL
#if LOG_LEVEL < LOG_LEVEL_WARNING
#undef LOGw
#undef LOGLw
#define LOGw DummyPrintf
#define LOGLw DummyPrintf
#endif // LOG_LEVEL_WARNING
#if LOG_LEVEL < LOG_LEVEL_INFO
#undef LOGi
#undef LOGLi
#define LOGi DummyPrintf
#define LOGLi DummyPrintf
#endif // LOG_LEVEL_INFO
#if LOG_LEVEL < LOG_LEVEL_DEBUG
#undef LOGd
#undef LOGLd
#define LOGd DummyPrintf
#define LOGLd DummyPrintf
#endif // LOG_LEVEL_DEBUG
#if LOG_LEVEL < LOG_LEVEL_VERBOSE
#undef LOGv
#undef LOGLv
#define LOGv DummyPrintf
#define LOGLv DummyPrintf
#endif // LOG_LEVEL_VERBOSE

// util macro
#define DUMP(path, addr, size) \
    FILE *fp = fopen(path, "wb"); \
    fwrite(addr, 1, size, fp); \
    fclose(fp);

// inline functions
static INLINE size_t inl_strlen(const char *str1)
{
    const char* p = str1;
    while(*p) p++;
    return p - str1;
}

static INLINE int inl_stricmp(const char *str1, const char *str2)
{
    int i=0;
    while(str1[i]!=0 && str2[i]!=0)
    {
        if (str1[i] == str2[i] 
        || str1[i] + 0x20 == str2[i] 
        || str2[i] + 0x20 == str1[i])
        {
            i++;
        }
        else
        {
            return (int)str1[i] - (int)str2[i];
        }
    }
    return (int)str1[i] - (int)str2[i];
}

static INLINE int inl_stricmp2(const char *str1, const wchar_t *str2)
{
    int i=0;
    while(str1[i]!=0 && str2[i]!=0)
    {
        if ((wchar_t)str1[i] == str2[i] 
        || (wchar_t)str1[i] + 0x20 == str2[i] 
        || str2[i] + 0x20 == (wchar_t)str1[i])
        {
            i++;
        }
        else
        {
            return (int)str1[i] - (int)str2[i];
        }
    }
    return (int)str1[i] - (int)str2[i];
}

static INLINE int inl_wcsicmp(const wchar_t *str1, const wchar_t *str2)
{
    int i = 0;
    while (str1[i] != 0 && str2[i] != 0)
    {
        if (str1[i] == str2[i]
            || str1[i] + 0x20 == str2[i]
            || str2[i] + 0x20 == str1[i])
        {
            i++;
        }
        else
        {
            return (int)str1[i] - (int)str2[i];
        }
    }
    return (int)str1[i] - (int)str2[i];
}

static INLINE uint32_t inl_crc32(const void *buf, size_t n)
{
    uint32_t crc32 = ~0;
    for(size_t i=0; i< n; i++)
    {
        crc32 ^= *(const uint8_t*)((uint8_t*)buf+i);

        for(int i = 0; i < 8; i++)
        {
            uint32_t t = ~((crc32&1) - 1); 
            crc32 = (crc32>>1) ^ (0xEDB88320 & t);
        }
    }
    return ~crc32;
}

static INLINE void* inl_memset(void *buf, int ch, size_t n)
{
    char *p = (char *)buf;
    for(size_t i=0;i<n;i++) p[i] = (char)ch;
    return buf;
}

static INLINE void* inl_memcpy(void *dst, const void *src, size_t n)
{
    char *p1 = (char*)dst;
    char *p2 = (char*)src;
    for(size_t i=0;i<n;i++) p1[i] = p2[i];
    return dst;
}

static INLINE size_t inl_hexifya(char *dst, size_t dstlen, const uint8_t *src, size_t srcsize, const char *sep)
{
    size_t srcpos = 0;
    size_t dstpos = 0;
    size_t sepsize = 0;
    if(sep)
    {
        while (sep[sepsize]) sepsize++;
    }  
    for(srcpos=0; srcpos < srcsize; srcpos++)
    {
        uint8_t c1 = src[srcpos] & 0xf;
        c1 = c1 >= 10 ? c1 - 10 + 'A': c1 + '0';
        uint8_t c2 = src[srcpos] >> 4;
        c2 = c2 >= 10 ? c2 - 10 + 'A': c2 + '0';
        if(dstpos+2 < dstlen)
        {
            dst[dstpos++] = (char)c2;
            dst[dstpos++] = (char)c1;
        }
        else
        {
            break;
        }
        if(dstpos + sepsize < dstlen)
        {
            for(size_t j=0; j < sepsize; j++)
            {
                dst[dstpos++] = sep[j];
            }
        }
    }
    dst[dstpos] = '\0';
    return srcpos;
}

static INLINE size_t inl_hexifyw(wchar_t *dst, size_t dstlen, const uint8_t *src, size_t srcsize, const wchar_t *sep)
{
    size_t srcpos = 0;
    size_t dstpos = 0;
    size_t sepsize = 0;
    if(sep)
    {
        while (sep[sepsize]) sepsize++;
    }  
    for(srcpos=0; srcpos < srcsize; srcpos++)
    {
        uint16_t c1 = src[srcpos] & 0xf;
        c1 = c1 >= 10 ? c1 - 10 + L'A': c1 + L'0';
        uint16_t c2 = src[srcpos] >> 4;
        c2 = c2 >= 10 ? c2 - 10 + L'A': c2 + L'0';
        if(dstpos+2 < dstlen)
        {
            dst[dstpos++] = (wchar_t)c2;
            dst[dstpos++] = (wchar_t)c1;
        }
        else
        {
            break;
        }
        if(dstpos + sepsize < dstlen)
        {
            for(size_t j=0; j < sepsize; j++)
            {
                dst[dstpos++] = sep[j];
            }
        }
    }
    dst[dstpos] = L'\0';
    return srcpos;
}

static INLINE void* inl_search(void* addr, 
    size_t memsize, const char* pattern, size_t* pmatchsize)
{
    size_t i = 0;
    int matchend = 0;
    void* matchaddr = NULL;
    while (i < memsize)
    {
        int j = 0;
        int matchflag = 1;
        matchend = 0;
        while (1)
        {
            if (pattern[j] == 0x20)
            {
                j++;
                continue;
            }
            if (!pattern[j]) break;

            char _c1 = (((char*)addr)[i + matchend] >> 4 ) & 0x0f;
            _c1 = _c1 < 10 ? _c1 + '0' : (_c1 - 10) + 'A';
            char _c2 = (((char*)addr)[i + matchend] & 0xf) & 0x0f;
            _c2 = _c2 < 10 ? _c2 + '0' : (_c2 - 10) + 'A';
            
            if (pattern[j] != '?')
            {
                
                if (_c1 != pattern[j] && _c1 + 0x20 != pattern[j])
                {
                    matchflag = 0;
                    break;
                }
            }
            else 
            {
                if(!pattern[j + 1]) 
                {
                    matchend++;
                    break;
                }
                if (pattern[j + 1] == 0x20) goto inl_search_next;
            }

            if(!pattern[j + 1]) 
            {
                matchend++;
                break;
            }
            if (pattern[j + 1] != '?')
            {
                if (_c2 != pattern[j + 1] && _c2 + 0x20 != pattern[j + 1])
                {
                    matchflag = 0;
                    break;
                }
            }
inl_search_next:
            j += 2;
            matchend++;
        }
        if (matchflag)
        {
            matchaddr = (void*)((uint8_t*)addr + i);
            break;
        }
        i++;
    }
    if (pmatchsize) *pmatchsize = matchend;
    return matchaddr;
}

#ifdef __cplusplus
}
#endif
#endif // _COMMDEF_H

/**
 * history
 * v0.1, initial version
 * v0.1.1, add hexifya, hexifyw, search
*/