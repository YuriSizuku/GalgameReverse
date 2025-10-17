#include <iostream>
#include <format>
#include <windows.h>

#ifdef _DEBUG
#define DEBUG_ONLY(...) __VA_ARGS__
#else
#define DEBUG_ONLY(...)
#endif

namespace G1WIN
{

    DEBUG_ONLY(static auto debug_log(std::string_view str, uint32_t cp = ::GetACP()) -> void
    {
        static HANDLE std_output_handle{};
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

    extern "C"
    {
        PVOID g_pfnOlds[];

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
    }
}