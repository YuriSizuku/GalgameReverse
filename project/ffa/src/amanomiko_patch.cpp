#include <iostream>
#include <format>
#include <windows.h>
#include <FontManager.hpp>

#ifdef _DEBUG
#define DEBUG_ONLY(...) __VA_ARGS__
#else
#define DEBUG_ONLY(...)
#endif

// 全局宏污染，因此取消定义
#ifdef DrawText
#undef DrawText
#endif
#ifdef min
#undef min
#endif
#ifdef max
#undef max
#endif

#if defined(_MSC_VER) && !defined(__clang__)
#define naked_function __declspec(naked, noinline)
#define Naked_Function __declspec(naked, noinline)
#define MSVC_COMPILER
#else
#define naked_function __attribute__((naked, noinline, used))
#define Naked_Function __attribute__((naked, noinline, used))
#endif

namespace G1WIN
{
    static Utils::FontManager FontManager{};

    static constexpr const UINT_PTR FONT_MENU_ID  { 0x114514   };
    static constexpr const wchar_t* FONT_MENU_TEXT{ L"更改字体" };

    DEBUG_ONLY(static HANDLE std_output_handle{});
    DEBUG_ONLY(static auto debug_log(std::string_view str, uint32_t cp = ::GetACP()) -> void
    {
        if (!std_output_handle)
        {
            ::AllocConsole();
            std_output_handle = ::GetStdHandle(STD_OUTPUT_HANDLE);
        }
        if (!std_output_handle)
        {
            return;
        }
        ::SetConsoleOutputCP(cp);
        ::WriteConsoleA(std_output_handle, str.data(), str.size(), NULL, NULL);
    })

    static auto get_current_path() -> std::string_view
    {
        static std::string path{};
        if (path.empty())
        {
            char szPath[1024]{};
            auto dwResult{ ::GetModuleFileNameA(NULL, szPath, 1024) };
            if (dwResult >= 1024)
            {
                return "";
            }
            std::string_view _path{ szPath };
            auto pos{ _path.rfind("\\") };
            if (pos != std::string_view::npos)
            {
                path.assign(_path.substr(0, pos + 1));
            }
        }
        return path;
    }

    static auto __cdecl PreparePaletteContext(HDC hdc) -> HGDIOBJ
    {
        return reinterpret_cast<decltype(PreparePaletteContext)*>(0x429CE0)(hdc);
    }

    static auto __cdecl RestorePalette(HDC hdc) -> HPALETTE
    {
        return reinterpret_cast<decltype(RestorePalette)*>(0x429D10)(hdc);
    }

    static auto __cdecl UpdateLayer(uintptr_t obj, int a2, int a3, int a4, int x, int y, int width, int height) -> int
    {
        return reinterpret_cast<decltype(UpdateLayer)*>(0x41BBA0)(obj, a2, a3, a4, x, y, width, height);
    }

    static auto __cdecl CharCount(int uchar) -> int
    {
        return (reinterpret_cast<decltype(CharCount)*>(0x44BD90)(uchar) != 0) + 1;
    }

    static auto DrawText(HDC hdc, const char* text, int count, int extra) -> SIZE
    {
        const auto& hTargetBitmap{ *reinterpret_cast<HGDIOBJ*>(0x45FA24) };
        const auto& hFont{ *reinterpret_cast<HGDIOBJ*>(0x45FC80) };

        const HDC hdcMem{ ::CreateCompatibleDC(hdc) };
        const HGDIOBJ hOldBmp{ ::SelectObject(hdcMem, hTargetBitmap) };
        const HGDIOBJ hOldFont{ hFont ? ::SelectObject(hdcMem, hFont) : nullptr };

        // 更换字体
        ::TEXTMETRIC tm{};
        ::GetTextMetricsA(hdcMem, &tm);
        auto tarFont = FontManager.GetGBKFont(tm.tmHeight);
        if (tarFont != nullptr)
        {
            ::SelectObject(hdcMem, tarFont);
        }

        // 清空画布上的内容
        BITMAP bmp{};
        ::GetObjectA(hTargetBitmap, sizeof(BITMAP), &bmp);
        ::BitBlt(hdcMem, 0, 0, bmp.bmWidth, bmp.bmHeight, NULL, 0, 0, BLACKNESS);

        // 设置背景以及文字颜色
        ::SetBkColor(hdcMem, RGB(0, 0, 0));
        ::SetTextColor(hdcMem, RGB(255, 255, 255));
        ::SetTextCharacterExtra(hdcMem, extra);

        // 绘制文字
        SIZE sizeTotal{};
        ::GetTextExtentPoint32A(hdcMem, text, count, &sizeTotal);
        ::TextOutA(hdcMem, 0, 0, text, count);

        ::SelectObject(hdcMem, hOldBmp);
        if (hOldFont)
        {
            SelectObject(hdcMem, hOldFont);
        }
        ::DeleteDC(hdcMem);

        return sizeTotal;
    }

    static auto __stdcall TargetDrawText(uintptr_t obj, const char** pStr, int width, int flag) -> void
    {
        auto&& x{ *reinterpret_cast<int*>(obj + 0x38) };
        auto&& y{ *reinterpret_cast<int*>(obj + 0x3C) };

        const char* pszText{ *pStr };
        const int charCount{ CharCount(*pszText) };
        if (!pszText || !*pszText)
        {
            *pStr += charCount;
            x += width;
            return;
        }

        const HWND hWnd{ *reinterpret_cast<HWND*>(obj + 0xA0) };
        const HDC   hdc{ ::GetDC(hWnd) };
        PreparePaletteContext(hdc);

        const auto dword_45FC58{ *reinterpret_cast<int**>(0x45FC58) };
        const int colorNormal{ dword_45FC58[1017] };
        const int flags{ dword_45FC58[1020] };
        const int configX{ dword_45FC58[1021] };
        const int configY{ dword_45FC58[1022] };

        const int renderX{ (configX >> 1) + x };
        const int renderY{ (configY >> 1) + y };

        auto sizeTotal = DrawText(hdc, pszText, charCount, 0);

        const int finalW{ configX + sizeTotal.cx };
        const int finalH{ configY + sizeTotal.cy };

        UpdateLayer(obj, 0, 0, colorNormal, renderX, renderY, finalW, finalH);

        if (flag == 1 && *reinterpret_cast<int*>(obj + 0x30) == 1)
        {
            HDC hdcMem = ::CreateCompatibleDC(hdc);
            HGDIOBJ hOldObj = ::SelectObject(hdcMem, *(HGDIOBJ*)(obj + 164));

            ::BitBlt(hdc, renderX, renderY, finalW, finalH, hdcMem, renderX, renderY, SRCCOPY);

            ::SelectObject(hdcMem, hOldObj);
            ::DeleteDC(hdcMem);
        }

        RestorePalette(hdc);
        ::ReleaseDC(hWnd, hdc);

        *pStr += charCount;
        x += sizeTotal.cx == 0 ? width : sizeTotal.cx / 2;
    }

    extern "C"
    {
        extern PVOID g_pfnOlds[];

        // 0x4226A0
        auto __cdecl check_RegKey_hook(const char* key) -> int
        {
            std::string_view _key{ key };

            DEBUG_ONLY(debug_log(std::format("check_RegKey_hook({})", std::string{ _key })));

            if (_key.ends_with("Path") || _key.ends_with("G1WIN.EXE"))
            {
                DEBUG_ONLY(debug_log(" -> 1\n"));
                return 1;
            }
            auto result = reinterpret_cast<decltype(check_RegKey_hook)*>(g_pfnOlds[3])(key);
            DEBUG_ONLY(debug_log(std::format(" -> {}\n", result)));
            return result;
        }

        // 0x422510
        auto __cdecl get_reg_value_hook(const char* key, char* lpData) -> int
        {
            std::string_view _key{ key };
            DEBUG_ONLY(debug_log(std::format("get_reg_value_hook({})\n", std::string{ _key })));

            if (_key.ends_with("Path"))
            {
                auto path{ get_current_path() };
                if (!path.empty())
                {
                    std::memcpy(lpData, path.data(), path.size());
                    lpData[path.size()] = '\0';
                    DEBUG_ONLY(debug_log(std::format(" -> 1 {}\n", path)));
                    return 1;
                }
            }
            auto result = reinterpret_cast<decltype(get_reg_value_hook)*>(g_pfnOlds[4])(key, lpData);
            DEBUG_ONLY(debug_log(std::format(" -> {} {}\n", result, lpData)));
            return result;
        }

        // 0x444590
        static auto CALLBACK JmpWndProc(void) -> void;

        auto CALLBACK WndProc_Hook(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam) -> LRESULT
        {
            const auto call_from_raw = reinterpret_cast<decltype(WndProc_Hook)*>(JmpWndProc);

            if (uMsg == WM_CREATE)
            {
                if (!G1WIN::FontManager.IsInit())
                {
                    G1WIN::FontManager.Init(hWnd, "G1WIN_CHS.font");
                }
                // 注册F1热键，在全屏时可用来打开字体选择器
                ::RegisterHotKey(hWnd, VK_F1, 0, VK_F1);
            }
            else if (uMsg == WM_HOTKEY)
            {
                if ((wParam & 0xFF) == VK_F1)
                {
                    ::SendMessageW(hWnd, WM_COMMAND, FONT_MENU_ID, NULL);
                }
                return TRUE;
            }
            else if (uMsg == WM_COMMAND && wParam == FONT_MENU_ID)
            {
                G1WIN::FontManager.GUIChooseFont();
                return TRUE;
            }
            else if (uMsg == WM_SIZE)
            {
                G1WIN::FontManager.GUIUpdateDisplayState();
            }

            return call_from_raw(hWnd, uMsg, wParam, lParam);
        }

        static Naked_Function auto CALLBACK JmpWndProc(void) -> void
        {
            #ifdef MSVC_COMPILER
            __asm
            {
                sub esp, 0x48
                push ebx
                push ebp
                mov ebp, dword ptr ss:[esp+0x58]
                push 0x444599
                ret
            }
            #else
            __asm__ __volatile__ 
            (
                "subl $0x48, %%esp;"      
                "pushl %%ebx;"            
                "pushl %%ebp;"            
                "movl 0x58(%%esp), %%ebp;"
    
                "pushl $0x444599;"
                "ret;"            
                :
                :
                : "cc", "memory"
            );
            #endif
        }

        // 0x41A7A4
        Naked_Function auto DrawText_Hook(void) -> void
        {
            #ifdef MSVC_COMPILER
            __asm
            {
                pushad

                mov  eax, dword ptr ss:[esp + 0x34] // 存储原始的width
                push edx  // flag :int
                push eax  // width:int
                push esi  // pStr :char**
                push edi  // info :void*
                call TargetDrawText

                popad

                push 0x041AB96
                ret
            }
            #else
            __asm__ __volatile__
            (
                "pushal;"                    
                "movl 0x34(%%esp), %%eax;"
                "pushl %%edx;"
                "pushl %%eax;"
                "pushl %%esi;"
                "pushl %%edi;"
                "call %P0;"
                "popal;"
                "pushl $0x041AB96;"
                "ret;"
                :
                : "i" (TargetDrawText)
                : "cc", "memory"
            );
            #endif
        }

        // 0x42D3EA
        Naked_Function auto AddFontManagerMenu(void) -> void
        {
            #ifdef MSVC_COMPILER
            __asm
            {
                pushad
                push FONT_MENU_TEXT
                push FONT_MENU_ID
                push MF_UNCHECKED
                push eax // hMenu
                call AppendMenuW
                popad

                test eax, eax
                jz __42D3C9
                push 0x42D3F5
                ret

            __42D3C9:
                push 0x42D3C9
                ret
            }
            #else
            __asm__ __volatile__
            (
                "pushal;"
                "pushl %[text];"
                "pushl %[id];"
                "pushl %[flag];"
                "pushl %%eax;"       
                "call %P[func];"     
                "popal;"             

                "testl %%eax, %%eax;"
                "jz 1f;"             

                "pushl $0x42D3F5;"
                "ret;"

                "1:"
                "pushl $0x42D3C9;"
                "ret;"
                
                : 
                : [text] "g" (FONT_MENU_TEXT),
                  [id]   "g" (FONT_MENU_ID),
                  [flag] "g" (MF_UNCHECKED),
                  [func] "s" (AppendMenuW)
                : "cc", "memory"
            );
            #endif
        }

        #ifdef libfontmanager
        
        PVOID g_pfnOlds[]{ nullptr };
        
        static auto JmpWrite(LPVOID OrgAddr, LPVOID TarAddr) -> bool
        {
            BYTE _Asm[5] = { 0xE9, 0x0, 0x0, 0x0, 0x0 };
            auto _Tar{ reinterpret_cast<DWORD>(TarAddr) };
            auto _Org{ reinterpret_cast<DWORD>(OrgAddr) };
            auto Addr{ static_cast<DWORD>(_Tar - _Org - 5) };
            *reinterpret_cast<DWORD*>(_Asm + 1) = Addr;

            DWORD  Protect{};
            SIZE_T Written{};
            if (::VirtualProtect(OrgAddr, sizeof(_Asm), PAGE_EXECUTE_READWRITE, &Protect))
            {
                static_cast<void>(WriteProcessMemory(INVALID_HANDLE_VALUE, OrgAddr, &_Asm, sizeof(_Asm), &Written));
                static_cast<void>(VirtualProtect(OrgAddr, sizeof(_Asm), Protect, &Protect));
                return sizeof(_Asm) == Written;
            }

            return FALSE;
        }
        
        auto APIENTRY DllMain(HMODULE, DWORD ul_reason_for_call, LPVOID) -> BOOL
        {
            if (DLL_PROCESS_ATTACH == ul_reason_for_call)
            {
                JmpWrite(reinterpret_cast<LPVOID>(0x444590), reinterpret_cast<LPVOID>(WndProc_Hook));
                JmpWrite(reinterpret_cast<LPVOID>(0x41A7A4), reinterpret_cast<LPVOID>(DrawText_Hook));
                JmpWrite(reinterpret_cast<LPVOID>(0x42D3EA), reinterpret_cast<LPVOID>(AddFontManagerMenu));
            }
            return { TRUE };
        }

        #endif
    }
}