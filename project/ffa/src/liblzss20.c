#define LZSS_IMPLEMENTATION
#define LZSS_SHARED
#define LZSS_DECINITBYTE 0X20
#define LZSS_ENCINITBYTE 0X20
#ifdef USE_COMPAT
#include "lzss_v1000.h"
#else
#include "lzss.h"
#endif