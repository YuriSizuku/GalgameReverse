/** 
 *  windows gdi32 dynamic binding
 *    v0.1, developed by devseed
 * 
 * macros:
 *    WINDYNGDI32_IMPLEMENTATION, include defines of each function
 *    WINDYN_SHARED, make function export
 *    WINDYN_STATIC, make function static
 *    WINDYN_NOINLINE, don't use inline function
*/

#ifndef _WINDYNGDI32_H
#define _WINDYNGDI32_H
#define WINDYNGDI32_VERSION "0.1"

#ifdef __cplusplus
extern "C" {
#endif
#include <windows.h>

#if 1 // winapi pointer declear
typedef HFONT (WINAPI *T_CreateFontA)(
    int cHeight,
    int cWidth,
    int cEscapement,
    int cOrientation,
    int cWeight,
    DWORD bItalic,
    DWORD bUnderline,
    DWORD bStrikeOut,
    DWORD iCharSet,
    DWORD iOutPrecision,
    DWORD iClipPrecision,
    DWORD iQuality,
    DWORD iPitchAndFamily,
    LPCSTR pszFaceName
);

typedef HFONT (WINAPI *T_CreateFontW)(
    int cHeight,
    int cWidth,
    int cEscapement,
    int cOrientation,
    int cWeight,
    DWORD bItalic,
    DWORD bUnderline,
    DWORD bStrikeOut,
    DWORD iCharSet,
    DWORD iOutPrecision,
    DWORD iClipPrecision,
    DWORD iQuality,
    DWORD iPitchAndFamily,
    LPCWSTR pszFaceName
);

typedef HFONT (WINAPI *T_CreateFontIndirectA)(
    CONST LOGFONTA *lplf
);

typedef HFONT (WINAPI *T_CreateFontIndirectW)(
    CONST LOGFONTW *lplf
);

typedef HFONT (WINAPI *T_CreateFontIndirectExA)(
    CONST ENUMLOGFONTEXDVA *
);

typedef HFONT (WINAPI *T_CreateFontIndirectExW)(
    CONST ENUMLOGFONTEXDVW *
);

typedef int (WINAPI *T_EnumFontFamiliesExA)(
    HDC hdc,
    LPLOGFONTA lpLogfont,
    FONTENUMPROCA lpProc,
    LPARAM lParam,DWORD dwFlags
);

typedef int (WINAPI *T_EnumFontFamiliesExW)(
    HDC hdc,
    LPLOGFONTW lpLogfont,
    FONTENUMPROCW lpProc,
    LPARAM lParam,
    DWORD dwFlags
);

typedef int (WINAPI *T_EnumFontFamiliesA)(
    HDC hdc,
    LPCSTR lpLogfont,
    FONTENUMPROCA lpProc,
    LPARAM lParam
);

typedef int (WINAPI *T_EnumFontFamiliesW)(
    HDC hdc,
    LPCWSTR lpLogfont,
    FONTENUMPROCW lpProc,
    LPARAM lParam
);

typedef int (WINAPI *T_EnumFontsA)(
    HDC hdc,
    LPCSTR lpLogfont,
    FONTENUMPROCA lpProc,
    LPARAM lParam
);

typedef int (WINAPI *T_EnumFontsW)(
    HDC hdc,LPCWSTR lpLogfont,
    FONTENUMPROCW lpProc,
    LPARAM lParam
);

typedef DWORD (WINAPI *T_GetGlyphOutlineA)(
    HDC hdc,
    UINT uChar,
    UINT fuFormat,
    LPGLYPHMETRICS lpgm,
    DWORD cjBuffer,
    LPVOID pvBuffer,
    CONST MAT2 *lpmat2
);

typedef DWORD (WINAPI *T_GetGlyphOutlineW)(
    HDC hdc,
    UINT uChar,
    UINT fuFormat,
    LPGLYPHMETRICS lpgm,
    DWORD cjBuffer,
    LPVOID pvBuffer,
    CONST MAT2 *lpmat2
);
#endif

#if 1 // windyn declear
#endif

#ifdef WINDYNGDI32_IMPLEMENTATION
#endif

#ifdef __cplusplus
}
#endif
#endif