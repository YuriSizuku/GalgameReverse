#pragma once
#include <FontManagerGUI.hpp>
#include <unordered_map>

namespace Utils {

    class FontManager
    {
        std::unique_ptr<FontManagerGUI> m_GUI{};
        std::unordered_map<int32_t, HFONT> m_Fonts{};

    public:

        const inline static int DefaultSize{ 30 };
        const inline static int UseCharSet
        {
            ::GetACP() == 936 ? ANSI_CHARSET : GB2312_CHARSET
        };
        
        inline FontManager() {}

        inline FontManager(HWND hWnd, bool check = false);

        auto Init(HWND hWnd, std::string_view storageConfig) -> FontManager&;

        auto IsInit() const -> bool;

        auto GetGBKFont (int32_t size) -> HFONT;

        auto GetSJISFont(int32_t size) -> HFONT;

        auto GUI() -> FontManagerGUI*;

        auto GUIUpdateDisplayState() -> FontManager&;

        auto GUIChooseFont() -> FontManager&;
    };
}
