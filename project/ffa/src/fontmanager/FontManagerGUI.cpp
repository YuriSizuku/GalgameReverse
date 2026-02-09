#include <iostream>
#include <string>
#include <thread>
#include <filesystem>
#include <FontManagerGUI.hpp>
#pragma comment(lib, "Comctl32.lib")
#pragma comment(linker,"\"/manifestdependency:type='win32' \
	name='Microsoft.Windows.Common-Controls' version='6.0.0.0' \
	processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")

extern "C" IMAGE_DOS_HEADER __ImageBase;

namespace Utils 
{

	auto CALLBACK FontManagerGUI::FontListBox::EnumProc(ENUMLOGFONTEX* lpelfe, NEWTEXTMETRICEX* lpntme, DWORD fontType, LPARAM lParam) -> int
    {
        if (fontType == TRUETYPE_FONTTYPE && lpelfe->elfLogFont.lfFaceName[0] != 0x40)
        {
            std::wstring_view name{ lpelfe->elfLogFont.lfFaceName };
			if (!name.empty())
            {
				if (m_this->defaultIndex == -1 && name == reinterpret_cast<wchar_t*>(lParam))
                {
					m_this->defaultIndex = m_this->GetCount();
				}
				m_this->AddItem(lpelfe->elfLogFont.lfFaceName);
			}
		}
		return 1;
	}

	auto CALLBACK FontManagerGUI::ManagerWndProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) -> LRESULT
    {
		switch (uMsg)
		{
		case WM_PAINT:
        {
			m_this->InitDisplay();
			break;
		}
		case WM_CTLCOLORBTN:
		case WM_CTLCOLORSTATIC:
        {
			::SetBkColor(reinterpret_cast<HDC>(wParam), m_this->DefaultBackgroundColor);
			return reinterpret_cast<LRESULT>(m_this->DefaultSolidBrush);
		}
		case WM_COMMAND:
        {
			if (LOWORD(wParam) == m_this->m_FontListBox.IDC && HIWORD(wParam) == LBN_SELCHANGE)
            {
                std::wstring&& name{ m_this->m_FontListBox.GetCurrentName() };
				if (!name.empty() && name != m_this->currentData.name) 
				{
					::wcscpy_s(m_this->currentData.name, name.c_str());
					m_this->m_FszGroupBox.nameEditor.SetTextW(m_this->currentData.name);
					m_this->UpdateDisplay(true);
				}
			}
			else if (LOWORD(wParam) == m_this->m_ResetButton.IDC)
            {
				if (std::memcmp(&m_this->currentData, &m_this->defaultData, sizeof(FontManagerGUI::Data)))
                {
					m_this->currentData = m_this->defaultData;
					m_this->UpdateBoxState().UpdateDisplay(true);

                    auto failed = bool
                    {
                        m_this->m_FontListBox.ResetDefault() == -1 &&
                        m_this->m_FontListBox.SelectItem(m_this->currentData.name) == LB_ERR
                    };
					if (failed)
					{
                        m_this->m_FontListBox.UnSelectItem();
						//m_this->m_FontListBox.SendMessage(LB_SETCURSEL, -1, 0);
					}
				}
			}
			else if (LOWORD(wParam) == m_this->m_ApplyButton.IDC)
            {
				m_this->StorageData();

                std::wstring&& name{ m_this->m_FszGroupBox.nameEditor.GetTextW() };
				if (!name.empty() && name != m_this->currentData.name)
				{
					::wcscpy_s(m_this->currentData.name, name.c_str());
					if (m_this->m_FontListBox.SelectItem(name.c_str()) == LB_ERR)
                    {
                        m_this->m_FontListBox.UnSelectItem();
						//m_this->m_FontListBox.SendMessage(LB_SETCURSEL, -1, 0);
					}
					m_this->UpdateDisplay();
				}
				m_this->lastData = m_this->currentData;
				m_this->m_DataUpdate = false;
				m_this->SetTextW(L"字体设置");
                m_this->OnChanged();
			}

			break;
		}
		case WM_CLOSE:
        {
			if (m_this->m_DataUpdate)
            {
				if (::MessageBoxW(m_this->m_hwnd, L"是否应用当前字体样式？", L"*未应用", MB_YESNO) != IDYES)
                {
					m_this->currentData = m_this->lastData;
				}
				else
                {
					m_this->OnChanged();
				}
				m_this->UpdateBoxState().UpdateDisplay().StorageData();
				m_this->m_DataUpdate = false;
			}
			m_this->m_OnChoosing = false;
			m_this->HideWindow();
			return TRUE;
		}
		case WM_NCRBUTTONDOWN: return NULL;
		default: break;
		}

		return m_this->m_proc(hwnd, uMsg, wParam, lParam);
	}


	auto CALLBACK FontManagerGUI::FszGroupBox::Editor::EditorProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) -> LRESULT
    {
        // ctrl + a 全选文本框内容
		if (uMsg == WM_CHAR && wParam == 0x01)
        {   
			return ::SendMessageW(hwnd, EM_SETSEL, 0, -1);
		}

        // 按下回车键事件，将当前字体设置搜索结果的第一个结果
		if (uMsg == WM_CHAR && wParam == 0x0D)
        {
            std::wstring&& text{ m_this->GetTextW() };
			if (text.empty())
            {
				m_this->SetTextW(m_this->manager->currentData.name);
				m_this->manager->UpdateDisplay(true);
			}
            else
            {
                int index{ m_this->manager->m_FontListBox.FindItem(text.c_str(), false) };
                if (LB_ERR != index && index != m_this->manager->m_FontListBox.GetCurrentIndex())
                {
                    m_this->manager->m_FontListBox.SelectItem(index);
                    auto&& name = m_this->manager->m_FontListBox.GetCurrentName();
                    ::wcscpy_s(m_this->manager->currentData.name, 30, name.c_str());
                    m_this->SetTextW(m_this->manager->currentData.name);
                    m_this->manager->UpdateDisplay(true);
                }
            }
		}
		return m_this->m_proc(hwnd, uMsg, wParam, lParam);
	}

	auto CALLBACK FontManagerGUI::FszGroupBox::BoxProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) -> LRESULT
    {
		if (::GetDlgCtrlID(HWND(lParam)) == m_this->nameEditor.IDC && uMsg == WM_COMMAND && HIWORD(wParam) == EN_CHANGE)
        {
			if (auto&& text = m_this->nameEditor.GetTextW(); text.empty())
            {
				m_this->manager->m_FontListBox.ResetTopIndex();
			}
			else
            {
				m_this->manager->m_FontListBox.FindItem(text.c_str(), false);
			}
			return TRUE;
		}
		if (::GetDlgCtrlID(HWND(lParam)) == m_this->trackBar.IDC && uMsg == WM_HSCROLL)
        {
			m_this->manager->currentData.size = m_this->trackBar.GetValue();
			m_this->sizeText.SetValue(m_this->manager->currentData.size);
			m_this->manager->UpdateDisplay(true);
		}

		if(uMsg == WM_CTLCOLORSTATIC ) {
			::SetBkColor(reinterpret_cast<HDC>(wParam), m_this->manager->DefaultBackgroundColor);
			return reinterpret_cast<LRESULT>(m_this->manager->DefaultSolidBrush);
		}
		return m_this->m_proc(hwnd, uMsg, wParam, lParam);
	}
	
	auto CALLBACK FontManagerGUI::FontListBox::BoxProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) -> LRESULT
    {
		return m_this->m_proc(hwnd, uMsg, wParam, lParam);
	}

	auto CALLBACK FontManagerGUI::StyGroupBox::BoxProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) -> LRESULT
    {
		if (uMsg == WM_COMMAND && HIWORD(wParam) == BN_CLICKED)
        {
			if (m_this->manager->currentData.style != Style(LOWORD(wParam)))
            {
				m_this->manager->currentData.style = Style(LOWORD(wParam));
				m_this->manager->UpdateDisplay(true);
			}
			return TRUE;
		}
		if(uMsg == WM_CTLCOLORSTATIC)
        {
			::SetBkColor(reinterpret_cast<HDC>(wParam), m_this->manager->DefaultBackgroundColor);
			return reinterpret_cast<LRESULT>(m_this->manager->DefaultSolidBrush);
		}
		return m_this->m_proc(hwnd, uMsg, wParam, lParam);
	}

	inline FontManagerGUI::FontListBox::FontListBox(FontManagerGUI* manager, HFONT font, HINSTANCE hInstance) :
        WindowBase(WS_EX_LTRREADING, WC_LISTBOX, WS_VISIBLE | WS_CHILD | WS_VSCROLL | WS_BORDER |
            LBS_HASSTRINGS | LBS_NOTIFY, 15, 85, 275, 240, manager->m_hwnd, hInstance, NULL),
        manager(manager)
	{
		this->SetFont(font).SetProc(FontListBox::BoxProc);
	}

	inline auto FontManagerGUI::FontListBox::Init(const wchar_t* name, LOGFONT logfont) const -> const FontManagerGUI::FontListBox&
    {
		::EnumFontFamiliesExW(this->GetDC(), &logfont, FONTENUMPROCW(FontListBox::EnumProc), LPARAM(name), NULL);
		return *this;
	}

	inline auto FontManagerGUI::FontListBox::Init(const wchar_t* name) const -> const FontManagerGUI::FontListBox&
    {
		return this->Init(name, { NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, ANSI_CHARSET });
	}

	inline auto FontManagerGUI::FontListBox::AddItem(const wchar_t* item) const -> int
    {
		return this->SendMessage(LB_ADDSTRING, 0, LPARAM(item));
	}

	inline auto FontManagerGUI::FontListBox::GetCount() const -> int {
		return this->SendMessage(LB_GETCOUNT, 0, 0);
	}

	inline auto FontManagerGUI::FontListBox::SelectItem(int index) const -> int
    {
		if (index == -1) return LB_ERR;
		return this->SendMessage(LB_SETCURSEL, index, 0);
	}

	inline auto FontManagerGUI::FontListBox::SelectItem(const wchar_t* name, bool exact) const -> int
    {
        int index{ this->FindItem(name, exact, false) };
		if (LB_ERR != index)
        {
			return this->SelectItem(index);
		}
		return LB_ERR;
	}

	inline auto FontManagerGUI::FontListBox::FindItem(const wchar_t* name, bool exact, bool redraw) const -> int
    {
        LRESULT index
        {
            this->SendMessage(exact ? LB_FINDSTRINGEXACT : LB_FINDSTRING, -1, LPARAM(name))
        };

		if (index != LB_ERR && redraw)
        {
			this->SetTopIndex(static_cast<int>(index));
		}
		return index;
	}

	inline auto FontManagerGUI::FontListBox::GetTopIndex() const -> int
    {
		return this->SendMessage(LB_GETTOPINDEX, 0, 0);
	}

	inline auto FontManagerGUI::FontListBox::SetTopIndex(int index) const -> int
    {
        this->SendMessage(LB_SETTOPINDEX, index, 0);
		return this->GetTopIndex();
	}

	inline auto FontManagerGUI::FontListBox::ResetTopIndex() const -> int
    {
		return this->SetTopIndex(this->GetCurrentIndex());
	}

	inline auto FontManagerGUI::FontListBox::ResetDefault() const -> int
    {
		if (this->defaultIndex != -1)
        {
			this->SelectItem(this->defaultIndex);
		}
		return this->defaultIndex;
	}

    inline auto FontManagerGUI::FontListBox::UnSelectItem() const -> void
    {
        static_cast<void>(this->SendMessage(LB_SETCURSEL, -1, 0));
    }

    inline auto FontManagerGUI::FontListBox::GetItemTextLength(int index) const -> int
    {
        return static_cast<int>(this->SendMessage(LB_GETTEXTLEN, index, 0));
    }

    inline auto FontManagerGUI::FontListBox::GetItemText(int index) const -> std::wstring
    {
        if (int length{ this->GetItemTextLength(index) };  length != LB_ERR)
        {
            std::wstring result(length, 0);
            if (this->SendMessage(LB_GETTEXT, index, LPARAM(result.data())) != LB_ERR)
            {
                return result;
            }
        }
        return std::wstring{ L"" };
    }

	inline auto FontManagerGUI::FontListBox::GetCurrentIndex() const -> int
    {
		return this->SendMessage(LB_GETCURSEL, 0, 0);
	}

	inline auto FontManagerGUI::FontListBox::GetCurrentName() const -> std::wstring
    {
        return this->GetItemText(this->GetCurrentIndex());
	}

	inline FontManagerGUI::FszGroupBox::FszGroupBox(FontManagerGUI* manager, HFONT font, HINSTANCE hInstance) :
        WindowBase(WS_EX_LTRREADING, L"BUTTON", L"字体＆大小", WS_VISIBLE | WS_CHILD | BS_GROUPBOX | BS_CENTER,
            305, 75, 220, 115,manager->m_hwnd, hInstance),
        nameEditor(manager, this->m_hwnd, font, hInstance),
        trackBar(this->m_hwnd, hInstance),
		sizeText(this->m_hwnd, font, hInstance),
        manager(manager)
	{
		this->SetFont(font).SetProc(FszGroupBox::BoxProc);
		this->nameEditor.SetLimitText(30);
	}

	inline FontManagerGUI::FszGroupBox::Editor::Editor(FontManagerGUI* manager, HWND parent, HFONT font, HINSTANCE hInstance):
        WindowBase(WS_EX_CLIENTEDGE, L"EDIT", WS_VISIBLE | WS_CHILD | ES_MULTILINE, 10, 30, 200, 30, parent, hInstance),
        manager(manager)
	{
		this->SetFont(font).SetProc(Editor::EditorProc);
	}

	inline auto FontManagerGUI::FszGroupBox::Editor::SetLimitText(int limit) const -> void
    {
		this->SendMessage(EM_LIMITTEXT, limit, NULL);
	}

	inline auto FontManagerGUI::FszGroupBox::Editor::SelectAllText() const -> void
    {
		this->SendMessage(EM_SETSEL, 0, -1);
	}

	inline FontManagerGUI::FszGroupBox::Trackbar::Trackbar(HWND parent, HINSTANCE hInstance): WindowBase(
        WS_EX_LTRREADING, TRACKBAR_CLASS, WS_CHILD | WS_VISIBLE | TBS_AUTOTICKS, 10, 75, 170, 30, parent, hInstance)
    {
	}

	inline auto FontManagerGUI::FszGroupBox::Trackbar::SetRange(int min, int max, bool redraw) const -> const Trackbar&
    {
		return this->SendMessage(TBM_SETRANGE, redraw, MAKELPARAM(min, max)), * this;
	}
	
	inline auto FontManagerGUI::FszGroupBox::Trackbar::SetValue(int value, bool redraw) const -> const Trackbar&
    {
		return this->SendMessage(TBM_SETPOS, redraw, value), *this;
	}

	inline auto Utils::FontManagerGUI::FszGroupBox::Trackbar::GetValue() const -> int
    {
		return this->SendMessage(TBM_GETPOS, 0, 0);
	}

	inline auto FontManagerGUI::FszGroupBox::Trackbar::Set(int min, int max, int value, bool redraw) const -> const Trackbar&
    {
		return this->SetRange(min, max).SetValue(value, redraw);
	}

	inline FontManagerGUI::FszGroupBox::SizeText::SizeText(HWND parent, HFONT font, HINSTANCE hInstance) :
        WindowBase(WS_EX_LTRREADING, L"STATIC", WS_VISIBLE | WS_CHILD, 185, 75, 20, 20, parent, hInstance)
    {
		this->SetFont(font);
	}

	inline auto FontManagerGUI::FszGroupBox::SizeText::SetValue(int value) const -> bool
    {
		return this->SetTextW(std::to_wstring(value).c_str());
	}

	inline FontManagerGUI::StyGroupBox::StyGroupBox(FontManagerGUI* manager, HFONT font, HINSTANCE hInstance):
        WindowBase(WS_EX_LTRREADING, L"BUTTON", L"字体样式", WS_VISIBLE | WS_CHILD | BS_GROUPBOX |
            BS_CENTER, 305, 195, 220, 75, manager->m_hwnd, hInstance), manager(manager),
        button1(this->m_hwnd, font, hInstance),  button2(this->m_hwnd, font, hInstance),
        button3(this->m_hwnd, font, hInstance),  button4(this->m_hwnd, font, hInstance)
    {
		this->SetFont(font).SetProc(StyGroupBox::BoxProc);
	}

	auto FontManagerGUI::StyGroupBox::SetChecked(uint16_t btn) const -> bool
    {
		switch (btn)
		{
		case StyGroupBox::Button1::IDC:
			this->button1.Checked();
			this->button2.UnChecked();
			this->button3.UnChecked();
			this->button4.UnChecked();
			return true;
		case StyGroupBox::Button2::IDC:
			this->button1.UnChecked();
			this->button2.Checked();
			this->button3.UnChecked();
			this->button4.UnChecked();
			return true;
		case StyGroupBox::Button3::IDC:
			this->button1.UnChecked();
			this->button2.UnChecked();
			this->button3.Checked();
			this->button4.UnChecked();
			return true;
		case StyGroupBox::Button4::IDC:
			this->button1.UnChecked();
			this->button2.UnChecked();
			this->button3.UnChecked();
			this->button4.Checked();
			return true;
		default: return false;
		}
	}

	inline auto FontManagerGUI::StyGroupBox::GetChecked() const -> uint16_t
    {
		if (this->button1.IsChecked())
        {
			return this->button1.IDC;
		}
		if (this->button2.IsChecked())
        {
			return this->button2.IDC;
		}
		if (this->button3.IsChecked())
        {
			return this->button3.IDC;
		}
		if (this->button4.IsChecked())
        {
			return this->button4.IDC;
		}
		return NULL;
	}
	
	FontManagerGUI::ActCtxHelper::ActCtxHelper()
    {
        auto actCtx = ACTCTX
        {
            .cbSize  = sizeof(ACTCTX),
            .dwFlags = ACTCTX_FLAG_HMODULE_VALID | ACTCTX_FLAG_RESOURCE_NAME_VALID,
            .lpResourceName = MAKEINTRESOURCE(2),
            .hModule = reinterpret_cast<HMODULE>(&__ImageBase)
        };
		this->m_ActCtx = CreateActCtxW(&actCtx);
	}

	FontManagerGUI::ActCtxHelper::~ActCtxHelper()
    {
		if (this->m_ActCtx && this->m_ActCtx != INVALID_HANDLE_VALUE)
        {
			::ReleaseActCtx(this->m_ActCtx);
		}
		this->m_ActCtx = { };
	}

	auto FontManagerGUI::ActCtxHelper::Get() const -> HANDLE
    {
		return this->m_ActCtx;
	}

	auto FontManagerGUI::ActCtxHelper::Activate() -> bool
    {
		if (this->m_ActCtx != INVALID_HANDLE_VALUE)
        {
			return ::ActivateActCtx(this->m_ActCtx, &this->m_Cookie);
		}
		return false;
	}

	auto FontManagerGUI::ActCtxHelper::Deactivate() -> bool
    {
        auto result{ ::DeactivateActCtx(0, this->m_Cookie) };
		this->m_Cookie = {};
		return static_cast<bool>(result);
	}

	auto FontManagerGUI::Init(Data defaultData, int minSize, int maxSize) -> FontManagerGUI&
    {
		this->m_FszGroupBox.trackBar.SetRange(minSize, maxSize, false);
		this->m_FontListBox.Init(defaultData.name);
		return this->defaultData = defaultData, *this;
	}

	auto FontManagerGUI::Init(int size, Style style, std::wstring_view name, int minSize, int maxSize) -> FontManagerGUI&
    {
		this->defaultData = Data{ int16_t(size), style };
		this->m_FszGroupBox.trackBar.SetRange(minSize, maxSize, false);

        size_t length{ name.length() };
		if (length >0 && length < 32)
        {
			::wcscpy_s(this->defaultData.name, name.data());
			this->m_FontListBox.Init(name.data());
		}
		return *this;
	}

	auto FontManagerGUI::Load(Data currentData) -> FontManagerGUI&
    {
		return this->Load(currentData.size, currentData.style, currentData.name);
	}

	auto FontManagerGUI::Load(int size, Style style, std::wstring_view name) -> FontManagerGUI&
    {
		this->currentData = Data{ int16_t(size), style };

        size_t length{ name.length() };
		if (length > 0 && length < 32)
        {
			::wcscpy_s(this->currentData.name, name.data());
		}

		this->m_FszGroupBox.trackBar.SetValue(currentData.size);
		this->m_FszGroupBox.sizeText.SetValue(currentData.size);
		this->m_FszGroupBox.nameEditor.SetTextW(currentData.name);
		this->m_FontListBox.SelectItem(currentData.name);
		this->m_StyGroupBox.SetChecked(currentData.style);
		return *this;
	}

	auto FontManagerGUI::Load(std::string_view storageFilePath, bool init) -> FontManagerGUI&
    {
		if (!storageFilePath.empty())
        {
			if (FILE* file = std::fopen(storageFilePath.data(), "rb"))
            {
				std::fseek(file, 0, SEEK_END);
				if (std::ftell(file) >= sizeof(Data))
                {
					std::rewind(file);
					std::fread(&this->currentData, sizeof(Data), 1, file);
					std::fclose(file);
				}
			}
			else if(init)
            {
				this->currentData = this->defaultData;
				this->StorageData(storageFilePath);
			}
			this->m_storageFilePath.assign(storageFilePath);
			this->UpdateBoxState();
		}
		return *this;
	}

	auto FontManagerGUI::StorageData(std::string_view storageFilePath) const -> bool
    {
        if (storageFilePath.empty())
        {
            return false;
        }

        auto&& dir{ std::filesystem::path(storageFilePath).parent_path() };
		if (!dir.string().empty())
        {
			if (!std::filesystem::exists(dir))
            {
				std::filesystem::create_directories(dir);
			}
		}

		if (FILE* file = std::fopen(storageFilePath.data(), "wb"))
        {
			size_t result = std::fwrite(&this->currentData, sizeof(Data), 1, file);
			std::fclose(file);
			return result == 1;
		}
		return false;
	}

	auto FontManagerGUI::StorageData() const -> bool
    {
		return this->StorageData(this->m_storageFilePath.c_str());
	}

	auto FontManagerGUI::OnChanged(Callback callback) -> FontManagerGUI&
    {
		this->m_Callback = callback;
		return *this;
	}
	auto FontManagerGUI::OnChanged(std::function<void(int32_t size, Style style, const std::wstring_view name)> callback) -> FontManagerGUI&
    {
		return this->OnChanged(
            [callback](const FontManagerGUI* m_this) -> void
            {
			    callback(m_this->currentData.size, m_this->currentData.style, m_this->currentData.name);
		    }
        );
	}

	auto FontManagerGUI::GetData() const -> const Data &
    {
		return this->currentData;
	}

	auto FontManagerGUI::ShowWindow(bool topMost) const -> BOOL
    {
		int x{ CW_USEDEFAULT }, y{ CW_USEDEFAULT }, width{ 550 }, height{ 355 };
        {
            RECT rect{};
            bool success
            {
                this->m_Parent.GetRect(rect) ||
                ::GetWindowRect(::GetDesktopWindow(), &rect)
            };
            if (success)
            {
                x = ((rect.left + rect.right) / 2) - (width / 2);
                y = ((rect.top + rect.bottom) / 2) - (height / 2);
            }
        }
		// ::EnableWindow(this->m_Parent.m_hwnd, static_cast<BOOL>(!topMost));
		::SetWindowPos(this->m_hwnd, topMost ? HWND_TOPMOST: HWND_NOTOPMOST, x, y, NULL, NULL, SWP_NOSIZE | SWP_NOACTIVATE);
		::SetForegroundWindow(this->m_hwnd);
		return ::ShowWindow(this->m_hwnd, SW_SHOW);
	}

	auto FontManagerGUI::HideWindow() const-> BOOL {
		if (!::IsWindowEnabled(this->m_Parent.m_hwnd))
        {
			::EnableWindow(this->m_Parent.m_hwnd, TRUE);
		}
		return ::ShowWindow(m_this->m_hwnd, SW_HIDE);
	}

	auto FontManagerGUI::IsFullScreen() const -> bool
    {
        int nScreenWidth { GetSystemMetrics(SM_CXSCREEN) };
        int nScreenHeight{ GetSystemMetrics(SM_CYSCREEN) };
        auto lStyle{ this->m_Parent.Get(GWL_STYLE) };
        RECT rect  { this->m_Parent.GetRect() };
        return bool
        {
            (lStyle & WS_POPUP) == WS_POPUP &&
            rect.left <= 0 && rect.top <= 0 &&
            rect.right >= nScreenWidth &&
            rect.bottom >= nScreenHeight
        };
	}

    auto FontManagerGUI::OnChanged() -> void
    {
        if (this->m_Callback != nullptr)
        {
            this->m_Callback(this);
        }
    }

	auto FontManagerGUI::MessageLoop() const -> void
    {
		std::thread([](HWND hwnd,MSG msg = { NULL })
        {
			while (::GetMessageW(&msg, hwnd, 0, 0) > 0)
            {
				::TranslateMessage(&msg);
				::DispatchMessageW(&msg);
			}
		}, this->m_hwnd).detach();
	}

	auto FontManagerGUI::ChooseFont() -> FontManagerGUI&
    {
		this->lastData = this->currentData;
		this->m_OnChoosing = true;
		this->ShowWindow(this->IsFullScreen());
		return *this;
	}

	auto Utils::FontManagerGUI::ChooseFont(std::function<void(int32_t size, Style style, const std::wstring_view name)> callback) -> FontManagerGUI&
    {
		std::thread([this, callback]()
        {
			this->ChooseFont().Wait();
			callback(this->currentData.size, this->currentData.style, this->currentData.name);
		}).detach();
		return *this;
	}

	auto FontManagerGUI::Wait() -> FontManagerGUI&
    {
        while (this->m_OnChoosing)
        {
            ::Sleep(1);
        };
		return *this;
	}

	auto Utils::FontManagerGUI::MakeFont(DWORD iCharSet, int baseSize) const -> HFONT
    {
        const wchar_t* name
        {
            std::wcslen(this->currentData.name) > 0 ?
            this->currentData.name : this->defaultData.name
        };
        const Style& style
        {
            this->currentData.style ?
            this->currentData.style : this->defaultData.style
        };
        auto bItalic = int
        {
            style & static_cast<uint16_t>(0x0F00) ?
            TRUE : FALSE
        };
        auto cWeight = int
        {
            style & static_cast<uint16_t>(0x00F0) ?
            FW_BOLD : FW_NORMAL
        };
        auto tarSize = int
        {
            this->currentData.size > 0 ?
            this->currentData.size : this->defaultData.size
        } + baseSize;
        auto result = HFONT
        {
            ::CreateFontW
            (
                { tarSize  },
                { 0x000000 },
                { 0x000000 },
                { 0x000000 },
                { cWeight  },
                { static_cast<uint32_t>(bItalic) },
                { FALSE    },
                { FALSE    },
                { iCharSet },
                { OUT_DEFAULT_PRECIS  },
                { CLIP_DEFAULT_PRECIS },
                { CLEARTYPE_QUALITY   },
                { DEFAULT_PITCH | FF_DONTCARE },
                { name      }
            )
        };
        return { result };
	}

	auto Utils::FontManagerGUI::MakeDefualtFont(DWORD iCharSet, int baseSize) const -> HFONT
    {
        auto tarSize = int
        {
            this->defaultData.size + baseSize
        };
        auto cWeight = int
        {
            this->defaultData.style& static_cast<uint16_t>(0x00F0) ?
            FW_BOLD : FW_NORMAL
        };
        auto bItalic = int
        {
            this->defaultData.style& static_cast<uint16_t>(0x0F00) ?
            TRUE : FALSE
        };
		auto result = HFONT
        {
            ::CreateFontW
            (
                { tarSize  },
                { 0x000000 },
                { 0x000000 },
                { 0x000000 },
                { cWeight  },
                { static_cast<uint32_t>(bItalic) },
                { FALSE    },
                { FALSE    },
                { iCharSet },
                { OUT_DEFAULT_PRECIS  },
                { CLIP_DEFAULT_PRECIS },
                { CLEARTYPE_QUALITY   },
                { DEFAULT_PITCH | FF_DONTCARE },
                { this->defaultData.name      }
            )
        };
        return { result };
	}

	FontManagerGUI::FontManagerGUI(HWND parent, HFONT font, HINSTANCE hInstance) : WindowBase(
		WS_EX_LTRREADING, FontManagerGUI::ManagerClassName, L"字体设置", WS_SYSMENU | WS_CAPTION, NULL,
		NULL, 550, 375, NULL, NULL, NULL, hInstance), m_hFont(font), m_StyGroupBox(this, font, hInstance),
		m_ApplyButton(this->m_hwnd, font, hInstance), m_ResetButton(this->m_hwnd, font, hInstance),
		m_FszGroupBox(this, font, hInstance), m_FontListBox(this, font, hInstance), m_Parent(parent)
	{
		this->SetFont(font).SetProc(FontManagerGUI::ManagerWndProc);
		this->SetIcon(reinterpret_cast<HICON>(::GetClassLongW(parent, GCLP_HICON)));
	}

	auto FontManagerGUI::InitDisplay(SIZE size, PAINTSTRUCT ps) -> FontManagerGUI&
    {
		static wchar_t text[]{ L"※请适当调整字体大小，过大过小都可能会导致游戏内显示异常。" };
        HDC hdc{ ::BeginPaint(this->m_hwnd, &ps) };
		::FillRect(hdc, &ps.rcPaint, this->DefaultSolidBrush);
		::SelectObject(hdc, this->m_hFont);
		::SetTextColor(hdc, RGB(193, 0, 0));
		::GetTextExtentPoint32W(hdc, text, (sizeof(text) - 2) / 2, &size);
		::SetBkMode(hdc, TRANSPARENT);
		::TextOutW(hdc, ((550 - size.cx) / 2), 316, text, (sizeof(text) - 2) / 2);
		::EndPaint(this->m_hwnd, &ps);
		return this->UpdateDisplay();
	}

	auto FontManagerGUI::UpdateDisplay(bool state) -> FontManagerGUI&
    {
        SIZE size{};
        PAINTSTRUCT ps{};
		static const RECT rect{ 0, 0, 550, 70 };
		static wchar_t text[]{ L"这是一段测试字体样式的文字。" };

        this->SetTextW(state ? L"字体设置 *未应用" : L"字体设置");
        ::InvalidateRect(this->m_hwnd, &rect, TRUE);

        HDC hdc{ ::BeginPaint(this->m_hwnd, &ps) };
		::FillRect(hdc, &rect, (HBRUSH)(COLOR_WINDOW + 1));

        HFONT&& hFont{ this->MakeFont() };
		::SelectObject(hdc, hFont);
		::SetTextColor(hdc, RGB(0, 0, 0));
		::SetTextCharacterExtra(hdc, 2);
		::GetTextExtentPoint32W(hdc, text, (sizeof(text) - 2) / 2, &size);

        int x{ ((550 - size.cx) / 2) }, y{ ((70 - size.cy) / 2) };
		::TextOutW(hdc, x, y, text, (sizeof(text) - 2) / 2);

		::EndPaint(this->m_hwnd, &ps);
		::DeleteObject(hFont);
		this->m_DataUpdate = state;
		return *this;
	}

	auto Utils::FontManagerGUI::UpdateBoxState() -> FontManagerGUI&
    {
		this->m_FszGroupBox.nameEditor.SetTextW(this->currentData.name);
		this->m_FszGroupBox.trackBar.SetValue(this->currentData.size);
		this->m_FszGroupBox.sizeText.SetValue(this->currentData.size);
		this->m_StyGroupBox.SetChecked(this->currentData.style);
		this->m_FontListBox.SelectItem(this->currentData.name);
		return *this;
	}

	auto FontManagerGUI::IsWindowVisible() -> bool
    {
		return static_cast<bool>(::IsWindowVisible(this->m_hwnd));
	}

	auto FontManagerGUI::UpdateDisplayState() -> FontManagerGUI&
    {
		if (this->IsWindowVisible())
        {
			this->ShowWindow(this->IsFullScreen());
		}
		return *this;
	}

	auto FontManagerGUI::Init(INITCOMMONCONTROLSEX icc, WNDCLASSEX cls) -> void
    {
		::InitCommonControlsEx(&icc);
		cls.lpfnWndProc = ::DefWindowProcW;
		cls.lpszClassName = FontManagerGUI::ManagerClassName;
		::RegisterClassExW(&cls);
	}

	auto FontManagerGUI::CreatePtr(HWND parent, HFONT hFont, HINSTANCE hInstance) -> std::unique_ptr<FontManagerGUI>
    {
		FontManagerGUI::Init();
		FontManagerGUI::VisStyActCtx->Activate();
        auto result{ std::unique_ptr<FontManagerGUI>(new FontManagerGUI(parent, hFont, hInstance)) };
		FontManagerGUI::VisStyActCtx->Deactivate();
		return result;
	}

	auto FontManagerGUI::CreatePtr(HFONT hFont, HINSTANCE hInstance) -> std::unique_ptr<FontManagerGUI>
    {
		return FontManagerGUI::CreatePtr(NULL, hFont, hInstance);
	}

	auto FontManagerGUI::CreatePtr(HWND parent, HINSTANCE hInstance) -> std::unique_ptr<FontManagerGUI>
    {
		return FontManagerGUI::CreatePtr
        (   parent,
            ::CreateFontW
            (
                20, 0, 0, 0, FW_NORMAL, FALSE, FALSE,
			    FALSE, ANSI_CHARSET, OUT_DEFAULT_PRECIS,
                CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
			    DEFAULT_PITCH | FF_DONTCARE, L"微软雅黑"
            ),
            hInstance
        );
	}
}
