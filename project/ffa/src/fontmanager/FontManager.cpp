#include <iostream>
#include <FontManager.hpp>

namespace Utils 
{
    inline FontManager::FontManager(HWND hWnd, bool check)
    {
        if (hWnd != nullptr) { this->Init(hWnd, "chs_font.dat"); }
    }

    auto FontManager::Init(HWND parent, std::string_view storageConfig) -> FontManager&
    {
        if (this->m_GUI == nullptr)
        {
            this->m_GUI = FontManagerGUI::CreatePtr(parent);
            if (this->m_GUI == nullptr)
            {
                return *this;
            }
        }

        this->m_GUI->Init(FontManager::DefaultSize, FontManagerGUI::NORMAL, L"黑体", 18, 48)
            .Load(storageConfig).OnChanged
            (
                [&](const FontManagerGUI* m_this) -> void
                {
                    for (auto& [key, font] : this->m_Fonts)
                    {
                        auto flag{ static_cast<int32_t>(key & 0xFF000000) };
                        auto size{ static_cast<int32_t>(key & 0x00FFFFFF) };
                        auto base{ static_cast<int32_t>(size - FontManager::DefaultSize) };

                        // flag为0x10是GBK，否则SJIS
                        auto charset{ flag == (0x10 << 24) ? this->UseCharSet : SHIFTJIS_CHARSET };
                        HFONT nFont { m_this->MakeFont(charset, base) };
                        HFONT oFont { font };

                        font = nFont;
                        if (oFont != nullptr)
                        {
                            ::DeleteObject(oFont);
                        }
                    }
                }
            );
        return *this;
    }

    auto FontManager::IsInit() const -> bool
    {
        return { this->m_GUI != nullptr };
    }

    auto FontManager::GetGBKFont(int32_t size) -> HFONT
    {
        int32_t key{ size | (0x10 << 24) };
        HFONT font { this->m_Fonts[key] };
        if (nullptr == font && this->m_GUI != nullptr)
        {
            auto base{ static_cast<int32_t>(size - FontManager::DefaultSize) };
            this->m_Fonts[key] = this->m_GUI->MakeFont(this->UseCharSet, base);
        }
        return this->m_Fonts[key];
    }

    auto FontManager::GetSJISFont(int32_t size) -> HFONT
    {
        int32_t key{ size | (0x20 << 24) };
        HFONT font{ this->m_Fonts[key] };
        if (nullptr == font && this->m_GUI != nullptr)
        {
            auto base{ static_cast<int32_t>(size - FontManager::DefaultSize) };
            this->m_Fonts[key] = this->m_GUI->MakeFont(SHIFTJIS_CHARSET, base);
        }
        return this->m_Fonts[key];
    }

    auto FontManager::GUI() -> FontManagerGUI*
    {
        return this->m_GUI.get();
    }

    auto FontManager::GUIUpdateDisplayState() -> FontManager&
    {
        if (this->m_GUI != nullptr)
        {
            this->m_GUI->UpdateDisplayState();
        }
        return *this;
    }

    auto FontManager::GUIChooseFont() -> FontManager&
    {
        if (this->m_GUI != nullptr)
        {
            this->m_GUI->ChooseFont();
        }
        return *this;
    }
}

