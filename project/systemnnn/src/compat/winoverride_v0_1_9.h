/**
 * single header file for overriding files, codepage and fonts
 *   v0.1.9 developed by devseed
 * 
 * macros:
 *    WINOVERRIDE_IMPLEMENTATION, include implements of each function
 *    WINOVERRIDE_SHARED, make function export
 *    WINOVERRIDE_STATIC, make function static
 *    WINOVERRIDE_REDIRECTDIRW, redirect dir
 *    WINOVERRIDE_NOFILE, remove file hook code
 *    WINOVERRIDE_NOCODEPAGE, remove codepage hook code
 *    WINOVERRIDE_NOFONT, remove font hook code
*/

#ifndef _WINOVERRIDE_H
#define _WINOVERRIDE_H

#ifdef __cplusplus
extern "C" {
#endif

#define WINOVERRIDE_VERSION "0.1.9"

#include <stdbool.h>
#ifdef USECOMPAT
#include "commdef_v0_1_1.h"
#else
#include "commdef.h"
#endif // USECOMPAT

// define specific macro
#ifndef WINOVERRIDE_API
#ifdef WINOVERRIDE_STATIC
#define WINOVERRIDE_API_DEF static
#else
#define WINOVERRIDE_API_DEF extern
#endif // WINOVERRIDE_STATIC
#ifdef WINOVERRIDE_SHARED
#define WINOVERRIDE_API_EXPORT EXPORT
#else  
#define WINOVERRIDE_API_EXPORT
#endif // WINOVERRIDE_SHARED
#define WINOVERRIDE_API WINOVERRIDE_API_DEF WINOVERRIDE_API_EXPORT
#endif // WINOVERRIDE_API

WINOVERRIDE_API
size_t winoverride_relpathw(const wchar_t *srcpath, const wchar_t *basepath, wchar_t *relpath);

WINOVERRIDE_API
int winoverride_patchpatternw(wchar_t *pattern);

WINOVERRIDE_API
void winoverride_install(bool init_minhook, const char *cfgpath);

WINOVERRIDE_API
void winoverride_uninstall(bool unint_minhook);

#ifdef WINOVERRIDE_IMPLEMENTATION
#include <windows.h>

#ifndef MINHOOK_IMPLEMENTATION
#define MINHOOK_IMPLEMENTATION
#define MINHOOK_STATIC
#endif

#ifdef USECOMPAT
#include "stb_minhook_v1_3_4.h"
#include "windynntdll_v0_1_1.h"
#include "windynkernel32_v0_1_7.h"
#include "windyngdi32_v0_1.h"
#else
#include "stb_minhook.h"
#include "windynntdll.h"
#include "windynkernel32.h"
#include "windyngdi32.h"
#endif

#ifndef WINOVERRIDE_REDIRECTDIRW
#define WINOVERRIDE_REDIRECTDIRW L"override"
#endif

struct winoverride_cfg_t
{
    bool override_file; // enable override file
    wchar_t redirectdir[MAX_PATH];
    bool override_codepage; // enable override codepage
    int codepage;
    bool forcecodepage;  // force override all codepage
    bool override_font; // enable override font
    int createfontcharset;
    int enumfontcharset;
    wchar_t fontname[32];
    wchar_t fontpath[MAX_PATH];
    wchar_t patch[1024];
    wchar_t dllpath[MAX_PATH];
};

static struct winoverride_cfg_t  g_winoverride_cfg = {
    .override_file = true,
    .redirectdir = WINOVERRIDE_REDIRECTDIRW,

    .override_codepage = false,
    .codepage = 0, .forcecodepage = false,

    .override_font = true,
    .createfontcharset = 0, .enumfontcharset = 0,
    .fontname = {L"\0"}, .fontpath = {L"\0"},

    .patch = {L"\0"}, .dllpath = {L"\0"}
};

#ifndef WINOVERRIDE_NOFILE
MINHOOK_DEFINE(NtCreateFile);
MINHOOK_DEFINE(NtOpenFile);
MINHOOK_DEFINE(NtCreateSection);
MINHOOK_DEFINE(NtCreateSectionEx);
MINHOOK_DEFINE(NtQueryAttributesFile);
MINHOOK_DEFINE(NtQueryFullAttributesFile);
MINHOOK_DEFINE(NtQueryInformationFile);
MINHOOK_DEFINE(NtQueryDirectoryFile);
MINHOOK_DEFINE(NtQueryDirectoryFileEx);

static BOOL _redirect_path(const POBJECT_ATTRIBUTES ObjectAttributes, wchar_t *rel, wchar_t *target)
{
    if(!ObjectAttributes || !ObjectAttributes->ObjectName || !rel || !target) return FALSE;
    wchar_t cwd[MAX_PATH] = { 0 };
    GetCurrentDirectoryW(MAX_PATH, cwd);
    if(winoverride_relpathw(ObjectAttributes->ObjectName->Buffer, cwd, rel))
    {
        if (wcsstr(ObjectAttributes->ObjectName->Buffer, L"\\??\\"))
        {
            wcscpy(target, L"\\??\\");
            if(!wcsstr(g_winoverride_cfg.redirectdir, L":"))
            {
                wcscat(target, cwd);
                wcscat(target, L"\\");
            }
        }
        wcscat(target, g_winoverride_cfg.redirectdir);
        wcscat(target, L"\\");
        wcscat(target, rel);
        return TRUE;
    }
    return FALSE;
}

static void _parse_query(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock,
    PVOID FileInformation, ULONG Length, FILE_INFORMATION_CLASS FileInformationClass)
{
    int i = 0;
    size_t cur = 0;
    PFILE_FULL_DIR_INFORMATION ffdirinfo = NULL;
    PFILE_BOTH_DIR_INFORMATION fbdirinfo = NULL;
    PFILE_STANDARD_INFORMATION fstdinfo = NULL;
    PFILE_NAME_INFORMATION fnameinfo = NULL;
    PFILE_ALL_INFORMATION fallinfo = NULL;

    switch ((int)FileInformationClass)
    {
    case 2: // FileFullDirectoryInformation (2)
        do
        {
            ffdirinfo = (PFILE_FULL_DIR_INFORMATION)((size_t)FileInformation + cur);
            // LOGLi(L"FileFullDirectoryInformation %d %ls\n", i, ffdirinfo->FileName);
            cur += ffdirinfo->NextEntryOffset;
            i++;
        } while (ffdirinfo->NextEntryOffset && cur < Length);
        break;
    case 3: // FileBothDirectoryInformation (3)
        do
        {
            fbdirinfo = (PFILE_BOTH_DIR_INFORMATION)((size_t)FileInformation + cur);
            // LOGLi(L"FileBothDirectoryInformation %d %ls\n", i, fbdirinfo->FileName);
            cur += fbdirinfo->NextEntryOffset;
            i++;
        } while (fbdirinfo->NextEntryOffset && cur < Length);
        break;
    case 5: // FileStandardInformation (5)
        fstdinfo = (PFILE_STANDARD_INFORMATION)FileInformation;
        break;
    case 9: // FileNameInformation (9)
    case 48: // FileNormalizedNameInformation
        fnameinfo = (PFILE_NAME_INFORMATION)FileInformation;
        break;
    case 14: // FilePositionInformation (14)
        break;
    case 18: // FileAllInformation (18)
        fallinfo = (PFILE_ALL_INFORMATION)FileInformation;
        break;
    case 68: // FileStatInformation (68)
        break;
    default:
        break;
    }
}

static NTSTATUS NTAPI NtCreateFile_hook( 
    OUT PHANDLE FileHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes,
    OUT PIO_STATUS_BLOCK IoStatusBlock,
    IN OPTIONAL PLARGE_INTEGER AllocationSize,
    IN ULONG FileAttributes,
    IN ULONG ShareAccess,
    IN ULONG CreateDisposition,
    IN ULONG CreateOptions,
    IN OPTIONAL PVOID EaBuffer,
    IN ULONG EaLength)
{
    MINHOOK_ENTERFUNC(NtCreateFile);
    NTSTATUS status = -1;
    BOOL flag_redirect = FALSE;
    wchar_t rel[MAX_PATH] = { 0 }, target[MAX_PATH] = { 0 };

    if(CreateOptions & FILE_DIRECTORY_FILE) // if dir
    {
        goto NtCreateFile_hook_end;
    }

    if ((DesiredAccess & FILE_GENERIC_READ) || (DesiredAccess & FILE_GENERIC_EXECUTE))
    {
        if(!_redirect_path(ObjectAttributes, rel, target)) goto NtCreateFile_hook_end;
        PUNICODE_STRING pustrorg = ObjectAttributes->ObjectName;
        UNICODE_STRING ustr = {(USHORT)wcslen(target) * 2, sizeof(target), target};
        ObjectAttributes->ObjectName = &ustr;
        status = pfn(FileHandle, DesiredAccess,
            ObjectAttributes, IoStatusBlock, AllocationSize,
            FileAttributes, ShareAccess, CreateDisposition,
            CreateOptions, EaBuffer, EaLength);
        ObjectAttributes->ObjectName = pustrorg;

        if (NT_SUCCESS(status))
        {
            flag_redirect = TRUE;
            LOGLi(L"REDIRECT %ls handle=%p\n", rel, *FileHandle);
        }
    }

NtCreateFile_hook_end:
    if (!flag_redirect)
    {
        status = pfn(FileHandle, DesiredAccess,
            ObjectAttributes, IoStatusBlock, AllocationSize,
            FileAttributes, ShareAccess, CreateDisposition,
            CreateOptions, EaBuffer, EaLength);
        if(rel[0]) LOGLi(L"FILE %ls %ld\n", rel, status);
    }

    MINHOOK_LEAVEFUNC(NtCreateFile);
    return status;
}

static NTSTATUS NTAPI NtOpenFile_hook(
    OUT PHANDLE FileHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes,
    OUT PIO_STATUS_BLOCK IoStatusBlock,
    IN ULONG ShareAccess,
    IN ULONG OpenOptions)
{
    MINHOOK_ENTERFUNC(NtOpenFile);
    NTSTATUS status = -1;
    BOOL flag_redirect = FALSE;
    wchar_t rel[MAX_PATH] = { 0 }, target[MAX_PATH] = { 0 };

    if (OpenOptions & FILE_DIRECTORY_FILE) // if dir
    {
		goto NtOpenFile_hook_end;
    }

    if ((DesiredAccess & FILE_GENERIC_READ) || (DesiredAccess & FILE_GENERIC_EXECUTE))
    {
        if (!_redirect_path(ObjectAttributes, rel, target)) goto NtOpenFile_hook_end;
        PUNICODE_STRING pustrorg = ObjectAttributes->ObjectName;
        UNICODE_STRING ustr = { (USHORT)wcslen(target) * 2, sizeof(target), target };
        ObjectAttributes->ObjectName = &ustr;
        status = pfn(FileHandle, DesiredAccess,
            ObjectAttributes, IoStatusBlock, ShareAccess, OpenOptions);
        ObjectAttributes->ObjectName = pustrorg;

        if (NT_SUCCESS(status))
        {
            flag_redirect = TRUE;
            LOGLi(L"REDIRECT %ls handle=%p\n", rel, *FileHandle);
        }
    }

NtOpenFile_hook_end:
    if (!flag_redirect)
    {
        status = pfn(FileHandle, DesiredAccess,
            ObjectAttributes, IoStatusBlock, ShareAccess, OpenOptions);
        if (rel[0]) LOGLi(L"FILE %ls %ld\n", rel, status);
    }

    MINHOOK_LEAVEFUNC(NtOpenFile);
    return status;
}

// might not used for check file
static NTSTATUS NTAPI NtCreateSection_hook(
    OUT PHANDLE SectionHandle,
    IN ACCESS_MASK DesiredAccess,
    IN OPTIONAL POBJECT_ATTRIBUTES ObjectAttributes,
    IN OPTIONAL PLARGE_INTEGER MaximumSize,
    IN ULONG SectionPageProtection,
    IN ULONG AllocationAttributes,
    IN OPTIONAL HANDLE FileHandle)
{
    MINHOOK_ENTERFUNC(NtCreateSection);
    NTSTATUS status = -1;
    status = pfn(SectionHandle, DesiredAccess,
        ObjectAttributes, MaximumSize, SectionPageProtection,
        AllocationAttributes, FileHandle);
    MINHOOK_LEAVEFUNC(NtCreateSection);
    return status;
}

static NTSTATUS NTAPI NtCreateSectionEx_hook(
    OUT PHANDLE SectionHandle,
    IN ACCESS_MASK DesiredAccess,
    IN OPTIONAL POBJECT_ATTRIBUTES ObjectAttributes,
    IN OPTIONAL PLARGE_INTEGER MaximumSize,
    IN ULONG SectionPageProtection,
    IN ULONG AllocationAttributes,
    IN OPTIONAL HANDLE FileHandle,
    IN OUT PVOID ExtendedParameters,
    ULONG ExtendedParameterCount)
{
    MINHOOK_ENTERFUNC(NtCreateSectionEx);
    NTSTATUS status = -1;
    status  = pfn(SectionHandle, DesiredAccess,
        ObjectAttributes, MaximumSize, SectionPageProtection, AllocationAttributes, 
        FileHandle, ExtendedParameters, ExtendedParameterCount);
    MINHOOK_LEAVEFUNC(NtCreateSectionEx);
    return status;
}

static NTSTATUS NTAPI NtQueryAttributesFile_hook(
    IN POBJECT_ATTRIBUTES   ObjectAttributes,
    OUT PFILE_BASIC_INFORMATION FileAttributes)
{
    MINHOOK_ENTERFUNC(NtQueryAttributesFile);
    NTSTATUS status = -1;
    status = pfn(ObjectAttributes, FileAttributes);
    MINHOOK_LEAVEFUNC(NtQueryAttributesFile);
    return status;
}

// this function is important for file size
static NTSTATUS NTAPI NtQueryFullAttributesFile_hook(
    IN POBJECT_ATTRIBUTES   ObjectAttributes,
    OUT PFILE_NETWORK_OPEN_INFORMATION  FileInformation)
{
    MINHOOK_ENTERFUNC(NtQueryFullAttributesFile);
    NTSTATUS status = -1;
    BOOL flag_redirect = FALSE;
    wchar_t rel[MAX_PATH] = { 0 }, target[MAX_PATH] = { 0 };

    if (!_redirect_path(ObjectAttributes, rel, target)) goto NtQueryFullAttributesFile_hook_end;
    PUNICODE_STRING pustrorg = ObjectAttributes->ObjectName;
    UNICODE_STRING ustr = { (USHORT)wcslen(target) * 2, sizeof(target), target };
    ObjectAttributes->ObjectName = &ustr;
    status = pfn(ObjectAttributes, FileInformation);
    ObjectAttributes->ObjectName = pustrorg;

    if (NT_SUCCESS(status))
    {
        flag_redirect = TRUE;
        LOGLi(L"REDIRECT %ls size=0x%llx\n", rel, FileInformation->EndOfFile.QuadPart);
    }

NtQueryFullAttributesFile_hook_end:
    if(!flag_redirect)
    {
        status = pfn(ObjectAttributes, FileInformation);
        if (rel[0] && NT_SUCCESS(status)) LOGLi(L"FILE %ls size=0x%llx\n", rel, FileInformation->EndOfFile.QuadPart);
    }

    MINHOOK_LEAVEFUNC(NtQueryFullAttributesFile);
    return status;
}

// might not need to redirect
static NTSTATUS NTAPI NtQueryInformationFile_hook(
    IN HANDLE FileHandle,
    OUT PIO_STATUS_BLOCK IoStatusBlock,
    OUT PVOID FileInformation,
    IN ULONG Length,
    IN FILE_INFORMATION_CLASS FileInformationClass)
{
    MINHOOK_ENTERFUNC(NtQueryInformationFile);
    NTSTATUS status = -1;
    status = pfn(FileHandle, IoStatusBlock, FileInformation, Length, FileInformationClass);
    // LOGLi(L"handle=%p %d\n", FileHandle, FileInformationClass);
    _parse_query(FileHandle, IoStatusBlock, FileInformation, Length, FileInformationClass);
    MINHOOK_LEAVEFUNC(NtQueryInformationFile);
    return status;
}

static NTSTATUS NTAPI NtQueryDirectoryFile_hook(
    IN HANDLE FileHandle,
    IN OPTIONAL HANDLE Event,
    IN OPTIONAL PIO_APC_ROUTINE ApcRoutine,
    IN OPTIONAL PVOID ApcContext,
    OUT PIO_STATUS_BLOCK IoStatusBlock,
    OUT PVOID FileInformation,
    IN ULONG Length,
    IN FILE_INFORMATION_CLASS FileInformationClass,
    IN BOOLEAN ReturnSingleEntry,
    IN OPTIONAL PUNICODE_STRING FileName,
    IN BOOLEAN RestartScan)
{
    MINHOOK_ENTERFUNC(NtQueryDirectoryFile);
    NTSTATUS status = -1;
    status  =  pfn(FileHandle, Event,
        ApcRoutine, ApcContext, IoStatusBlock,
        FileInformation, Length, FileInformationClass,
        ReturnSingleEntry, FileName, RestartScan);
    // LOGLi(L"handle=%p %d\n", FileHandle, FileInformationClass);
    _parse_query(FileHandle, IoStatusBlock, FileInformation, Length, FileInformationClass);
    MINHOOK_LEAVEFUNC(NtQueryDirectoryFile);
    return status;
}

static NTSTATUS NTAPI NtQueryDirectoryFileEx_hook(
    IN HANDLE FileHandle,
    IN HANDLE Event,
    IN OPTIONAL PIO_APC_ROUTINE ApcRoutine,
    IN OPTIONAL PVOID ApcContext,
    OUT PIO_STATUS_BLOCK IoStatusBlock,
    OUT PVOID FileInformation,
    IN ULONG Length,
    FILE_INFORMATION_CLASS FileInformationClass,
    IN ULONG QueryFlags,
    IN OPTIONAL PUNICODE_STRING FileName)
{
    MINHOOK_ENTERFUNC(NtQueryDirectoryFileEx);
    NTSTATUS status = -1;
    status = pfn(FileHandle, Event, ApcRoutine, ApcContext,
        IoStatusBlock, FileInformation, Length,
        FileInformationClass, QueryFlags, FileName);
    // LOGLi(L"handle=%p %d\n", FileHandle, FileInformationClass);
    _parse_query(FileHandle, IoStatusBlock, FileInformation, Length, FileInformationClass);
    MINHOOK_LEAVEFUNC(NtQueryDirectoryFileEx);
    return status;
}
#endif

#ifndef WINOVERRIDE_NOCODEPAGE
MINHOOK_DEFINE(MultiByteToWideChar);
MINHOOK_DEFINE(WideCharToMultiByte);
MINHOOK_DEFINE(GetACP);
MINHOOK_DEFINE(GetOEMCP);
MINHOOK_DEFINE(GetCPInfo);
MINHOOK_DEFINE(GetCPInfoExA);
MINHOOK_DEFINE(GetCPInfoExW);
MINHOOK_DEFINE(IsDBCSLeadByte);
MINHOOK_DEFINE(IsDBCSLeadByteEx);

static int WINAPI MultiByteToWideChar_hook(
    UINT CodePage, 
    DWORD dwFlags, 
    LPCCH lpMultiByteStr, 
    int cbMultiByte, 
    LPWSTR lpWideCharStr, 
    int cchWideChar)
{
    MINHOOK_ENTERFUNC(MultiByteToWideChar);
    if (g_winoverride_cfg.forcecodepage) CodePage = g_winoverride_cfg.codepage;
    else if (CodePage == CP_ACP) CodePage = g_winoverride_cfg.codepage;
    int res = pfn(CodePage, dwFlags, 
        lpMultiByteStr, cbMultiByte, lpWideCharStr, cchWideChar);
    MINHOOK_LEAVEFUNC(MultiByteToWideChar);
    return res;
}

static int WINAPI WideCharToMultiByte_hook(
    UINT CodePage, 
    DWORD dwFlags, 
    LPCWCH lpWideCharStr, 
    int cchWideChar, 
    LPSTR lpMultiByteStr, 
    int cbMultiByte, 
    LPCCH lpDefaultChar, 
    LPBOOL lpUsedDefaultChar)
{
    MINHOOK_ENTERFUNC(WideCharToMultiByte);
    if (g_winoverride_cfg.forcecodepage) CodePage = g_winoverride_cfg.codepage;
    else if (CodePage == CP_ACP) CodePage = g_winoverride_cfg.codepage;
    int res = pfn(CodePage, dwFlags, lpWideCharStr, cchWideChar, 
        lpMultiByteStr, cbMultiByte, lpDefaultChar, lpUsedDefaultChar);
    MINHOOK_LEAVEFUNC(WideCharToMultiByte);
    return res;
}

static UINT WINAPI GetACP_hook(void)
{
    MINHOOK_ENTERFUNC(GetACP);
    UINT res = pfn();
    if (g_winoverride_cfg.codepage) res =  g_winoverride_cfg.codepage;
    MINHOOK_LEAVEFUNC(GetACP);
    return res; 
}   

static UINT WINAPI GetOEMCP_hook(void)
{
    MINHOOK_ENTERFUNC(GetOEMCP);
    UINT res = pfn();
    if (g_winoverride_cfg.codepage) res =  g_winoverride_cfg.codepage;
    MINHOOK_LEAVEFUNC(GetOEMCP);
    return res;
}

static BOOL WINAPI GetCPInfo_hook(UINT CodePage, LPCPINFO lpCPInfo)
{
    MINHOOK_ENTERFUNC(GetCPInfo);
    if (g_winoverride_cfg.codepage) CodePage = g_winoverride_cfg.codepage;
    BOOL res = pfn(CodePage, lpCPInfo);
    MINHOOK_LEAVEFUNC(GetCPInfo);
    return res;
}

static BOOL WINAPI GetCPInfoExA_hook(UINT CodePage, DWORD dwFlags, LPCPINFOEXA lpCPInfoEx)
{
    MINHOOK_ENTERFUNC(GetCPInfoExA);
    if (g_winoverride_cfg.codepage) CodePage = g_winoverride_cfg.codepage;
    BOOL res = pfn(CodePage, dwFlags, lpCPInfoEx);
    MINHOOK_LEAVEFUNC(GetCPInfoExA);
    return res;
}

static BOOL WINAPI GetCPInfoExW_hook(UINT CodePage, DWORD dwFlags, LPCPINFOEXW lpCPInfoEx)
{
    MINHOOK_ENTERFUNC(GetCPInfoExW);
    if (g_winoverride_cfg.codepage) CodePage = g_winoverride_cfg.codepage;
    BOOL res = pfn(CodePage, dwFlags, lpCPInfoEx);
    MINHOOK_LEAVEFUNC(GetCPInfoExW);
    return res;
}

static BOOL WINAPI IsDBCSLeadByte_hook(BYTE TestChar)
{
    MINHOOK_ENTERFUNC(IsDBCSLeadByte);
    T_IsDBCSLeadByteEx pfn2 = IsDBCSLeadByteEx_org;
    BOOL res = g_winoverride_cfg.codepage ? pfn2(g_winoverride_cfg.codepage, TestChar) : pfn(TestChar);
    MINHOOK_LEAVEFUNC(IsDBCSLeadByte);
    return res;
}

static BOOL WINAPI IsDBCSLeadByteEx_hook(UINT CodePage, BYTE TestChar)
{
    MINHOOK_ENTERFUNC(IsDBCSLeadByteEx);
    if (g_winoverride_cfg.codepage) CodePage = g_winoverride_cfg.codepage;
    BOOL res = pfn(CodePage, TestChar);
    MINHOOK_LEAVEFUNC(IsDBCSLeadByteEx);
    return res;
}
#endif

#ifndef WINOVERRIDE_NOFONT
MINHOOK_DEFINE(CreateFontA)
MINHOOK_DEFINE(CreateFontW)
MINHOOK_DEFINE(CreateFontIndirectA)
MINHOOK_DEFINE(CreateFontIndirectW)
MINHOOK_DEFINE(CreateFontIndirectExA)
MINHOOK_DEFINE(CreateFontIndirectExW)
MINHOOK_DEFINE(EnumFontsA)
MINHOOK_DEFINE(EnumFontsW)
MINHOOK_DEFINE(EnumFontFamiliesA)
MINHOOK_DEFINE(EnumFontFamiliesW)
MINHOOK_DEFINE(EnumFontFamiliesExA)
MINHOOK_DEFINE(EnumFontFamiliesExW)

static HFONT WINAPI CreateFontA_hook(
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
    LPCSTR pszFaceName)
{
    MINHOOK_ENTERFUNC(CreateFontA);
    T_CreateFontW pfn2 = CreateFontW_org;
    HFONT hfont = NULL;
    if (g_winoverride_cfg.createfontcharset) iCharSet = g_winoverride_cfg.createfontcharset;
    if (g_winoverride_cfg.fontname[0]) hfont = pfn2(
        cHeight, cWidth, cEscapement, cOrientation,
        cWeight, bItalic, bUnderline, bStrikeOut,
        iCharSet, iOutPrecision, iClipPrecision, iQuality,
        iPitchAndFamily, g_winoverride_cfg.fontname);
    else pfn(cHeight, cWidth, cEscapement, cOrientation,
        cWeight, bItalic, bUnderline, bStrikeOut,
        iCharSet, iOutPrecision, iClipPrecision, iQuality,
        iPitchAndFamily, pszFaceName);
    MINHOOK_LEAVEFUNC(CreateFontA);
    return hfont;
}

static HFONT WINAPI CreateFontW_hook(
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
    LPCWSTR pszFaceName)
{
    MINHOOK_ENTERFUNC(CreateFontW);
    if (g_winoverride_cfg.createfontcharset) iCharSet = g_winoverride_cfg.createfontcharset;
    if (g_winoverride_cfg.fontname[0]) pszFaceName = g_winoverride_cfg.fontname;
    HFONT hfont = pfn(cHeight, cWidth, cEscapement, cOrientation,
        cWeight, bItalic, bUnderline, bStrikeOut,
        iCharSet, iOutPrecision, iClipPrecision, iQuality,
        iPitchAndFamily, pszFaceName);
    MINHOOK_LEAVEFUNC(CreateFontW);
    return hfont;
}

static HFONT WINAPI CreateFontIndirectA_hook(
    CONST LOGFONTA *lplf)
{
    MINHOOK_ENTERFUNC(CreateFontIndirectA);
    LOGFONTW lfw;
    memcpy(&lfw, lplf, sizeof(*lplf));
    HFONT hfont = NULL;
    T_CreateFontIndirectW pfn2 = CreateFontIndirectW_org;
    if (g_winoverride_cfg.createfontcharset) lfw.lfCharSet = g_winoverride_cfg.createfontcharset;
    if (g_winoverride_cfg.fontname[0])
    {
        wcscpy(lfw.lfFaceName, g_winoverride_cfg.fontname);
        hfont = pfn2(&lfw);
    }
    else
    {
        hfont = pfn((CONST LOGFONTA *)&lfw);
    }
    MINHOOK_LEAVEFUNC(CreateFontIndirectA);
    return hfont;
}

static HFONT WINAPI CreateFontIndirectW_hook(
    CONST LOGFONTW *lplf)
{
    MINHOOK_ENTERFUNC(CreateFontIndirectW);
    LOGFONTW lfw;
    memcpy(&lfw, lplf, sizeof(*lplf));
    HFONT hfont = NULL;
    if (g_winoverride_cfg.createfontcharset) lfw.lfCharSet = g_winoverride_cfg.createfontcharset;
    if (g_winoverride_cfg.fontname[0])
    {
        wcscpy(lfw.lfFaceName, g_winoverride_cfg.fontname);
    }
    hfont = pfn(&lfw);
    MINHOOK_LEAVEFUNC(CreateFontIndirectW);
    return hfont;
}

static HFONT WINAPI CreateFontIndirectExA_hook(
    CONST ENUMLOGFONTEXDVA *lplf)
{
    MINHOOK_ENTERFUNC(CreateFontIndirectExA);
    ENUMLOGFONTEXDVW lfw;
    memcpy(&lfw, lplf, sizeof(*lplf));
    HFONT hfont = NULL;
    T_CreateFontIndirectExW pfn2 = CreateFontIndirectExW_org;
    if (g_winoverride_cfg.createfontcharset) lfw.elfEnumLogfontEx.elfLogFont.lfCharSet = g_winoverride_cfg.createfontcharset;
    if (g_winoverride_cfg.fontname[0])
    {
        wcscpy(lfw.elfEnumLogfontEx.elfLogFont.lfFaceName, g_winoverride_cfg.fontname);
        hfont = pfn2(&lfw);
    }
    else
    {
        hfont = pfn((CONST ENUMLOGFONTEXDVA*)&lfw);
    }
    MINHOOK_LEAVEFUNC(CreateFontIndirectExA);
    return hfont;
}

static HFONT WINAPI CreateFontIndirectExW_hook(
    CONST ENUMLOGFONTEXDVW *lplf)
{
    MINHOOK_ENTERFUNC(CreateFontIndirectExW);
    ENUMLOGFONTEXDVW lfw;
    memcpy(&lfw, lplf, sizeof(*lplf));
    HFONT hfont = NULL;
    if (g_winoverride_cfg.createfontcharset) lfw.elfEnumLogfontEx.elfLogFont.lfCharSet = g_winoverride_cfg.createfontcharset;
    if (g_winoverride_cfg.fontname[0])
    {
        wcscpy(lfw.elfEnumLogfontEx.elfLogFont.lfFaceName, g_winoverride_cfg.fontname);
    }
    hfont = pfn(&lfw);
    MINHOOK_LEAVEFUNC(CreateFontIndirectExW);
    return hfont;
}

static FONTENUMPROCA fontenumproca_org = NULL;
static FONTENUMPROCW fontenumprocw_org = NULL;

static int CALLBACK fontenumproca_hook(
    CONST LOGFONTA *lglf,
    CONST TEXTMETRICA *lpntm,
    DWORD FontType,
    LPARAM aFontCount)
{
    int res = 0;
    if (!lglf || !lpntm || !fontenumproca_org) return res;
    if (g_winoverride_cfg.enumfontcharset)
    {
        ((LOGFONTA*)lglf)->lfCharSet = (BYTE)g_winoverride_cfg.enumfontcharset;
        ((TEXTMETRICA*)lpntm)->tmCharSet = (BYTE)g_winoverride_cfg.enumfontcharset;
    }
    res = fontenumproca_org(lglf, lpntm, FontType, aFontCount);
    return res;
}

static int CALLBACK fontenumprocw_hook(
    CONST LOGFONTW *lglf,
    CONST TEXTMETRICW *lpntm,
    DWORD FontType,
    LPARAM aFontCount)
{
    int res = 0;
    if (!lglf || !lpntm || !fontenumprocw_org) return res;
    if (g_winoverride_cfg.enumfontcharset)
    {
        ((LOGFONTW*)lglf)->lfCharSet = (BYTE)g_winoverride_cfg.enumfontcharset;
        ((TEXTMETRICW*)lpntm)->tmCharSet = (BYTE)g_winoverride_cfg.enumfontcharset;
    }
    // LOGLi(L"facename=%ls\n", lglf->lfFaceName);
    res = fontenumprocw_org(lglf, lpntm, FontType, aFontCount);
    return res;
}

static int WINAPI EnumFontsA_hook(
    HDC hdc,
    LPCSTR lpLogfont,
    FONTENUMPROCA lpProc,
    LPARAM lParam)
{
    MINHOOK_ENTERFUNC(EnumFontsA);
    fontenumproca_org = lpProc;
    int res = pfn(hdc, lpLogfont, fontenumproca_hook, lParam);
    MINHOOK_LEAVEFUNC(EnumFontsA);
    return res;
}

static int WINAPI EnumFontsW_hook(
    HDC hdc,
    LPCWSTR lpLogfont,
    FONTENUMPROCW lpProc,
    LPARAM lParam)
{
    MINHOOK_ENTERFUNC(EnumFontsW);
    fontenumprocw_org = lpProc;
    int res = pfn(hdc, lpLogfont, fontenumprocw_hook, lParam);
    MINHOOK_LEAVEFUNC(EnumFontsW);
    return res;
}

static int WINAPI EnumFontFamiliesA_hook(
    HDC hdc,
    LPCSTR lpLogfont,
    FONTENUMPROCA lpProc,
    LPARAM lParam)
{
    MINHOOK_ENTERFUNC(EnumFontFamiliesA);
    fontenumproca_org = lpProc;
    int res = pfn(hdc, lpLogfont, fontenumproca_hook, lParam);
    MINHOOK_LEAVEFUNC(EnumFontFamiliesA);
    return res;
}

static int WINAPI EnumFontFamiliesW_hook(
    HDC hdc,
    LPCWSTR lpLogfont,
    FONTENUMPROCW lpProc,
    LPARAM lParam)
{
    MINHOOK_ENTERFUNC(EnumFontFamiliesW);
    fontenumprocw_org = lpProc;
    int res = pfn(hdc, lpLogfont, fontenumprocw_hook, lParam);
    MINHOOK_LEAVEFUNC(EnumFontFamiliesW);
    return res;
}

static int WINAPI EnumFontFamiliesExA_hook(
    HDC hdc,
    LPLOGFONTA lpLogfont,
    FONTENUMPROCA lpProc,
    LPARAM lParam,DWORD dwFlags)
{
    MINHOOK_ENTERFUNC(EnumFontFamiliesExA);
    fontenumproca_org = lpProc;
    if (g_winoverride_cfg.createfontcharset) lpLogfont->lfCharSet = g_winoverride_cfg.createfontcharset;
    int res = pfn(hdc, lpLogfont, fontenumproca_hook, lParam, dwFlags);
    MINHOOK_LEAVEFUNC(EnumFontFamiliesExA);
    return res;
}

static int WINAPI EnumFontFamiliesExW_hook(
    HDC hdc,
    LPLOGFONTW lpLogfont,
    FONTENUMPROCW lpProc,
    LPARAM lParam,
    DWORD dwFlags)
{
    MINHOOK_ENTERFUNC(EnumFontFamiliesExW);
    fontenumprocw_org = lpProc;
    if (g_winoverride_cfg.createfontcharset) lpLogfont->lfCharSet = g_winoverride_cfg.createfontcharset;
    // LOGLi(L"facename=%ls\n", lpLogfont->lfFaceName);
    int res = pfn(hdc, lpLogfont, fontenumprocw_hook, lParam, dwFlags);
    MINHOOK_LEAVEFUNC(EnumFontFamiliesExW);
    return res;
}
#endif

#if 1 // winoverride_patch
size_t winoverride_relpathw(const wchar_t* srcpath, const wchar_t* basepath, wchar_t* relpath)
{
    if (!srcpath || !basepath || !relpath) return 0;

    relpath[0] = L'\0';
    if (wcslen(srcpath) >= 7 && wcsncmp(srcpath, L"\\Device", 7) == 0) return 0;
    if (wcslen(srcpath) >= 7 && wcsncmp(srcpath, L"\\DEVICE", 7) == 0) return 0;
    if (wcslen(srcpath) >= 4 && wcsncmp(srcpath, L"\\??\\", 4) == 0) // nt global path
    {

        if (wcsstr(srcpath + 4, basepath))
        {
            wcscpy(relpath, srcpath + 4 + wcslen(basepath));
        }
    }
    else
    {
        wcscpy(relpath, srcpath);
    }

    for (int i = 0; relpath[i]; i++)
    {
        if (relpath[i] == L'/') relpath[i] = L'\\';
    }

    int offset = 0;
    if (relpath[0] == L'\\') offset = 1;
    else if (relpath[0] == L'.' && relpath[1] == L'\\') offset = 2;
    if (offset > 0) wcsncpy(relpath, relpath + offset, wcslen(relpath) + 1 - offset);

    return wcslen(relpath);
}

int winoverride_patchpatternw(wchar_t *pattern)
{
    if (!pattern) return -1;
    size_t imagebase = (size_t)GetModuleHandleA(NULL);
    int res = 0;
    int flag_rel = 0;
    int j = 0;
    while (pattern[j]) j++;
    int patternlen = j;
    DWORD oldprotect;

    for (int i=0; i<patternlen; i++)
    {
        if (pattern[i] == L'#')
        {
            while (pattern[i] != L'\n' && i<patternlen) i++;
            continue;
        }
        else if (pattern[i] == L'\n' || pattern[i] == L'\r')
        {
            continue;
        }
        else if (pattern[i] == L'+')
        {
            flag_rel = 1;
            i++;
        }
        while (pattern[i] == L' ') i++;

        size_t addr = 0;
        int flag_nextline = 0;
        for (; pattern[i] != L':' && i<patternlen; i++)
        {
            char c = (char)pattern[i];
            if(c>='0' && c<='9') c -= '0';
            else if (c>='A' && c<='Z') c = c -'A' + 10;
            else if (c>='a' && c<='z') c = c -'a' + 10;
            else if (c=='\r' || c=='\n') {flag_nextline=1;break;}
            else if (c==' ') continue;
            else return -2;
            addr = (addr<<4) + c;
        }
        if(flag_nextline) continue;
        if(flag_rel) addr += imagebase;

        int n = 0;
        int v = 0;
        int start = i++;
        for (int j=0; j<2; j++)
        {
            n = 0;
            for (; pattern[i] != L'\n' && i<patternlen; i++)
            {
                char c = (char)pattern[i];
                if (c>='0' && c<='9') c -= '0';
                else if (c>='A' && c<='Z') c = c - 'A' + 10;
                else if (c>='a' && c<='z') c = c - 'a' + 10;
                else if (c==';') break;
                else continue;
                n++;
                if (j != 0)
                {
                    v = (v << 4) + c;
                    if (!(n & 1))
                    {
                        *(uint8_t*)(addr + (n>>1) -1) = v;
                        v = 0;
                        res++;
                    }
                }
            }
            if(n&1) return -3;
            if (j == 0)
            {
                i = start;
                VirtualProtect((void*)addr, n>>1, PAGE_EXECUTE_READWRITE, &oldprotect);
            }
            else VirtualProtect((void*)addr, n>>1, oldprotect, &oldprotect);
        }
        flag_rel = 0;
    }
    return res;
}
#endif

static bool winoverride_readcfg(const char *cfgpath)
{
    struct winoverride_cfg_t *cfg = &g_winoverride_cfg;
    FILE *fp = fopen(cfgpath, "rb");
    if (!fp)
    {
        LOGw("can not find %s\n", cfgpath);
        return false;
    }

    wchar_t line[1024] = {0};
    wchar_t *k = NULL;
    wchar_t *v = NULL;
    fread(line, 2, 1, fp); // skip bom
    if(line[0] != 0xfeff) fseek(fp, 0, SEEK_SET);

#define LOAD_CFG_INT(name) \
    if (!_wcsicmp(k, L"" #name)) cfg->name = _wtoi(v);
#define LOAD_CFG_STR(name) \
    if (!_wcsicmp(k, L"" #name)) wcscpy(cfg->name, v);
    while (fgetws(line, sizeof(line)/2, fp))
    {
        k = wcstok(line, L"=\n\r");
        v = wcstok(NULL, L"=\n\r");
        LOGLi(L"read config %ls=%ls\n", k, v);
        LOAD_CFG_INT(override_file);
        LOAD_CFG_STR(redirectdir);
        LOAD_CFG_INT(override_codepage);
        LOAD_CFG_INT(codepage);
        LOAD_CFG_INT(forcecodepage);
        LOAD_CFG_INT(override_font);
        LOAD_CFG_INT(createfontcharset);
        LOAD_CFG_INT(enumfontcharset);
        LOAD_CFG_STR(fontname);
        LOAD_CFG_STR(fontpath)
        LOAD_CFG_STR(patch);
        LOAD_CFG_STR(dllpath);
    }
#undef LOAD_CFG_INT
#undef LOAD_CFG_STR
    fclose(fp);
    return true;
}

void winoverride_install(bool init_minhook, const char *cfgpath)
{
    if (init_minhook)
    {
        MH_STATUS status = MH_Initialize();
        if (status != MH_OK)
        {
            LOGe("MH_Initialize failed with %s\n", MH_StatusToString(status));
        }
    }

    if (cfgpath) winoverride_readcfg(cfgpath);

#ifndef WINOVERRIDE_NOFILE
    if (g_winoverride_cfg.override_file)
    {
        HMODULE ntdll = GetModuleHandle("ntdll.dll");
        MINHOOK_BINDEXP(ntdll, NtCreateFile);
        MINHOOK_BINDEXP(ntdll, NtOpenFile);
        MINHOOK_BINDEXP(ntdll, NtCreateSection);
        MINHOOK_BINDEXP(ntdll, NtCreateSectionEx);
        MINHOOK_BINDEXP(ntdll, NtQueryAttributesFile);
        MINHOOK_BINDEXP(ntdll, NtQueryFullAttributesFile);
        MINHOOK_BINDEXP(ntdll, NtQueryInformationFile);
        MINHOOK_BINDEXP(ntdll, NtQueryDirectoryFile);
        MINHOOK_BINDEXP(ntdll, NtQueryDirectoryFileEx);
    }
#endif

#ifndef WINOVERRIDE_NOCODEPAGE
    if (g_winoverride_cfg.override_codepage)
    {
        HMODULE kernel32 = GetModuleHandleA("kernel32.dll");
        MINHOOK_BINDEXP(kernel32, MultiByteToWideChar);
        MINHOOK_BINDEXP(kernel32, WideCharToMultiByte);
        MINHOOK_BINDEXP(kernel32, GetACP);
        MINHOOK_BINDEXP(kernel32, GetOEMCP);
        MINHOOK_BINDEXP(kernel32, GetCPInfo);
        MINHOOK_BINDEXP(kernel32, GetCPInfoExA);
        MINHOOK_BINDEXP(kernel32, GetCPInfoExW);
        MINHOOK_BINDEXP(kernel32, IsDBCSLeadByte);
        MINHOOK_BINDEXP(kernel32, IsDBCSLeadByteEx);
    }
#endif

#ifndef WINOVERRIDE_NOFONT
    if (g_winoverride_cfg.override_font)
    {
        if (g_winoverride_cfg.fontpath[0])
        {
            int res = AddFontResourceW(g_winoverride_cfg.fontpath);
            LOGLi(L"AddFontResourceW %ls res=%d\n", g_winoverride_cfg.fontpath, res);
        }
        HMODULE gdi32 = GetModuleHandleA("gdi32.dll");
        MINHOOK_BINDEXP(gdi32, CreateFontA);
        MINHOOK_BINDEXP(gdi32, CreateFontW);
        MINHOOK_BINDEXP(gdi32, CreateFontIndirectA);
        MINHOOK_BINDEXP(gdi32, CreateFontIndirectW);
        MINHOOK_BINDEXP(gdi32, CreateFontIndirectExA);
        MINHOOK_BINDEXP(gdi32, CreateFontIndirectExW);
        MINHOOK_BINDEXP(gdi32, EnumFontsA);
        MINHOOK_BINDEXP(gdi32, EnumFontsW);
        MINHOOK_BINDEXP(gdi32, EnumFontFamiliesA);
        MINHOOK_BINDEXP(gdi32, EnumFontFamiliesW);
        MINHOOK_BINDEXP(gdi32, EnumFontFamiliesExA);
        MINHOOK_BINDEXP(gdi32, EnumFontFamiliesExW);
    }
#endif

    if (g_winoverride_cfg.patch[0])
    {
        int n = winoverride_patchpatternw(g_winoverride_cfg.patch);
        LOGi("applied %d patches\n", n);
    }
    if (g_winoverride_cfg.dllpath[0])
    {
        HMODULE hmod = LoadLibraryW(g_winoverride_cfg.dllpath);
        LOGLi(L"LoadLibraryW %ls hmod=%p\n", g_winoverride_cfg.dllpath, hmod);
    }
}

void winoverride_uninstall(bool uninit_minhook)
{
#ifndef WINOVERRIDE_NOFILE
    if (g_winoverride_cfg.override_file)
    {
        MINHOOK_UNBIND(NtCreateFile);
        MINHOOK_UNBIND(NtOpenFile);
        MINHOOK_UNBIND(NtCreateSection);
        MINHOOK_UNBIND(NtCreateSectionEx);
        MINHOOK_UNBIND(NtQueryAttributesFile);
        MINHOOK_UNBIND(NtQueryFullAttributesFile);
        MINHOOK_UNBIND(NtQueryInformationFile);
        MINHOOK_UNBIND(NtQueryDirectoryFile);
        MINHOOK_UNBIND(NtQueryDirectoryFileEx);
    }
#endif

#ifndef WINOVERRIDE_NOCODEPAGE
    if (g_winoverride_cfg.override_codepage)
    {
        MINHOOK_UNBIND(MultiByteToWideChar);
        MINHOOK_UNBIND(WideCharToMultiByte);
        MINHOOK_UNBIND(GetACP);
        MINHOOK_UNBIND(GetOEMCP);
        MINHOOK_UNBIND(GetCPInfo);
        MINHOOK_UNBIND(GetCPInfoExA);
        MINHOOK_UNBIND(GetCPInfoExW);
        MINHOOK_UNBIND(IsDBCSLeadByte);
        MINHOOK_UNBIND(IsDBCSLeadByteEx);
    }
#endif

#ifndef WINOVERRIDE_NOFONT
    if (g_winoverride_cfg.override_font)
    {
        if (g_winoverride_cfg.fontpath[0])
        {
            int res = RemoveFontResourceW(g_winoverride_cfg.fontpath);
            LOGLi(L"RemoveFontResourceW %ls res=%d\n", g_winoverride_cfg.fontpath, res);
        }
        MINHOOK_UNBIND(CreateFontA);
        MINHOOK_UNBIND(CreateFontW);
        MINHOOK_UNBIND(CreateFontIndirectA);
        MINHOOK_UNBIND(CreateFontIndirectW);
        MINHOOK_UNBIND(CreateFontIndirectExA);
        MINHOOK_UNBIND(CreateFontIndirectExW);
        MINHOOK_UNBIND(EnumFontsA);
        MINHOOK_UNBIND(EnumFontsW);
        MINHOOK_UNBIND(EnumFontFamiliesA);
        MINHOOK_UNBIND(EnumFontFamiliesW);
        MINHOOK_UNBIND(EnumFontFamiliesExA);
        MINHOOK_UNBIND(EnumFontFamiliesExW);
    }
#endif

    if (uninit_minhook)
    {
        MH_STATUS status = MH_Uninitialize();
        if(status != MH_OK)
        {
            LOGe("MH_Initialize failed with %s\n", MH_StatusToString(status));
        }
    }
}

#endif
#ifdef __cplusplus
}
#endif
#endif

/**
 * history:
 * v0.1, initial version
 * v0.1.1, seperate to single header file
 * v0.1.2, add NtOpenFile, relpathw string length check
 * v0.1.3, add NtCreateSection, NtCreateSectionEx,
 *         NtQueryAttributesFile, NtQueryFullAttributesFile,
 *         NtQueryInformationFile, NtQueryDirectoryFile
 * v0.1.4, add config file, disable directory override
 * v0.1.5, add redirectdir in config file
 * v0.1.6, support patch pattern
 * v0.1.7, add WINOVERRIDE_NOFILE, WINOVERRIDE_NOFONT, WINOVERRIDE_NOCODEPAGE
 * v0.1.8, support override codepage
 * v0.1.9, support override font
 */