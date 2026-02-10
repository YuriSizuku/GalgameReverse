#pragma once
#ifndef UNICODE
#define UNICODE
#endif
#include <windows.h>
#include <functional>
#include <commctrl.h>
#ifdef SendMessage
#undef SendMessage
#endif
#ifdef RegisterClass
#undef RegisterClass
#endif 
#ifdef CreateFont
#undef CreateFont
#endif
#ifdef ChooseFont
#undef ChooseFont
#endif

namespace Utils
{

	template<typename T, uint16_t idc> class WindowBase
	{
		friend T;
	protected:

		static inline T* m_this{ nullptr };
		decltype(::DefWindowProcW)* const m_proc{ nullptr };
		const HWND m_hwnd{ nullptr };

		inline WindowBase(): m_hwnd(nullptr), m_proc(nullptr){}
		 
		inline WindowBase(HWND hwnd) : m_hwnd(hwnd), m_proc(reinterpret_cast<decltype(m_proc)>(::GetWindowLongPtr(hwnd, GWLP_WNDPROC))){
			if constexpr (idc) WindowBase<T, idc>::m_this = reinterpret_cast<T*>(this);
		}

		inline ~WindowBase() { 
			if constexpr (idc) WindowBase<T, idc>::m_this = nullptr;
		}

		inline WindowBase(DWORD dwExStyle, LPCWSTR lpClassName, LPCWSTR lpWindowName, DWORD dwStyle, int X, int Y, int nWidth, int nHeight, HWND hWndParent,
			HMENU hMenu, HINSTANCE hInstance, LPVOID lpParam = NULL) : WindowBase(::CreateWindowExW(dwExStyle, lpClassName, lpWindowName, dwStyle, X, Y,
				nWidth, nHeight, hWndParent, hMenu, hInstance, lpParam)) {
		}

		inline WindowBase(DWORD dwExStyle, LPCWSTR lpClassName, LPCWSTR lpWindowName, DWORD dwStyle, int X, int Y, int nWidth, int nHeight, HWND hWndParent,
			HINSTANCE hInstance, LPVOID lpParam = NULL) : WindowBase(dwExStyle, lpClassName, lpWindowName, dwStyle, X, Y, nWidth, nHeight, hWndParent, 
				HMENU(IDC), hInstance, lpParam) {
		}

		inline WindowBase(DWORD dwExStyle, LPCWSTR lpClassName, DWORD dwStyle, int X, int Y, int nWidth, int nHeight, HWND hWndParent, HINSTANCE hInstance,
			LPVOID lpParam = NULL) : WindowBase(dwExStyle, lpClassName, L"", dwStyle, X, Y, nWidth, nHeight, hWndParent, HMENU(IDC), hInstance, lpParam) {
		}

		inline auto SetFont(HFONT hFont) -> T& {
			this->SendMessage(WM_SETFONT, WPARAM(hFont), TRUE);
			return *reinterpret_cast<T*>(this);
		}
	public:
		static inline constexpr uint16_t IDC = idc;
		static inline T* GetInstance() { return WindowBase<T, idc>::m_this; }

		inline auto GetTextW() const -> std::wstring {
			if (int length = ::GetWindowTextLengthW(this->m_hwnd); length != 0) {
				auto&& result = std::wstring(length, 0);
				::GetWindowTextW(this->m_hwnd, const_cast<wchar_t*>(result.c_str()), length + 1);
				return result;
			}
			return std::wstring(L"");
		}

		inline auto SetTextW(std::wstring_view text) const -> bool {
			return !text.empty() && ::SetWindowTextW(this->m_hwnd, text.data());
		}

		template<typename R = LRESULT>
		inline auto SendMessage(UINT Msg, WPARAM wParam, LPARAM lParam) const -> R {
			auto&& result = ::SendMessageW(this->m_hwnd, Msg, wParam, lParam);
			return *reinterpret_cast<R*>(&result);
		}

		inline auto GetDC() const -> HDC 
		{
			return ::GetDC(this->m_hwnd);
		}

		inline auto SetProc(decltype(::DefWindowProcW)* proc) const -> decltype(::DefWindowProcW)* 
		{
			return reinterpret_cast<decltype(::DefWindowProcW)*>(this->Set(GWLP_WNDPROC, proc));
		}

		template<typename P = LONG_PTR>
		inline auto Set(int nIndex, P nValue) const -> P
        {
            auto&& result
            {
                ::SetWindowLongPtrW(this->m_hwnd, nIndex, LONG_PTR(nValue))
            };
			return *reinterpret_cast<P*>(&result);
		}

		inline auto SetIcon(HICON hIcon, bool isBig = true) -> HICON
        {
			return this->SendMessage<HICON>(WM_SETICON, isBig, LPARAM(hIcon));
		}

		template<typename R = LONG_PTR>
        inline auto Get(int nIndex) const -> R
        {
			auto&& result = ::GetWindowLongW(this->m_hwnd, nIndex);
			return *reinterpret_cast<R*>(&result);
		}

        inline auto GetRect(RECT& rect) const -> bool
        {
            return static_cast<bool>(::GetWindowRect(this->m_hwnd, &rect));
        }

        inline auto GetRect() const -> RECT 
        {
            RECT rect{};
            ::GetWindowRect(this->m_hwnd, &rect);
			return rect;
		}
	};

	class FontManagerGUI : public WindowBase<FontManagerGUI, static_cast<uint16_t>(0xFFFF)> 
	{

		template<typename T, uint16_t idc> class ButtonBase : public WindowBase<T, idc>
		{
		protected:
			using WindowBase<T, idc>::WindowBase;
			inline ButtonBase(LPCWSTR text, DWORD dwStyle, int nWidth, int nHeight, int X, int Y, HWND parent, HFONT font, HINSTANCE hInstance) :
				WindowBase<T, idc>(WS_EX_LTRREADING, L"BUTTON", text, dwStyle, X, Y, nWidth, nHeight, parent, hInstance)
			{
				this->SetFont(font);
			}
		};

		class FontListBox : WindowBase<FontListBox, static_cast<uint16_t>(0x1000)> 
		{
			
			friend FontManagerGUI;

			static auto CALLBACK BoxProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam)->LRESULT;
			static auto CALLBACK EnumProc(ENUMLOGFONTEX* lpelfe, NEWTEXTMETRICEX* lpntme, DWORD fontType, LPARAM lParam) -> int;

		private:

			FontManagerGUI* const manager{};
			int defaultIndex{ -1 };

			inline auto Init(const wchar_t* name, LOGFONT logfont) const -> const FontListBox&;
			inline auto Init(const wchar_t* name) const -> const FontManagerGUI::FontListBox&;
			inline auto AddItem(const wchar_t* item) const -> int;

		public:
			using WindowBase::WindowBase;
			using WindowBase::operator=;

			inline FontListBox(FontManagerGUI* manager, HFONT font, HINSTANCE hInstance = ::GetModuleHandleW(NULL));
			~FontListBox() = default;

			inline auto GetCount() const -> int;
			inline auto SelectItem(int index) const -> int;
			inline auto SelectItem(const wchar_t* name, bool exact = true) const -> int;
			inline auto FindItem(const wchar_t* name, bool exact, bool redraw = true) const -> int;
			inline auto GetCurrentName() const -> std::wstring;
			inline auto GetCurrentIndex() const -> int;
			inline auto GetTopIndex() const -> int;
			inline auto SetTopIndex(int index) const -> int;
			inline auto ResetTopIndex() const -> int;
			inline auto ResetDefault() const -> int;
            inline auto UnSelectItem() const -> void;
            inline auto GetItemTextLength(int index) const -> int;
            inline auto GetItemText(int index) const -> std::wstring;
		};

		class FszGroupBox : public WindowBase<FszGroupBox, static_cast<uint16_t>(0x2000)> 
		{
			
			friend FontManagerGUI;

			class Editor : public WindowBase<Editor, FszGroupBox::IDC + 1> {
				friend FszGroupBox;
				using WindowBase::WindowBase;
				FontManagerGUI* const manager;
			private:
				static auto CALLBACK EditorProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) -> LRESULT;

				inline Editor(FontManagerGUI* manager, HWND parent, HFONT font, HINSTANCE hInstance);
				~Editor() = default;

				inline auto SetLimitText(int limit) const -> void;
			public:
				inline auto SelectAllText() const -> void;
			};

			class Trackbar : public WindowBase<Trackbar, FszGroupBox::IDC + 2> 
			{
				friend FszGroupBox;
				using WindowBase::WindowBase;
			private:
				inline Trackbar(HWND parent, HINSTANCE hInstance);
			public:
				inline auto SetRange(int min, int max, bool redraw = true) const -> const Trackbar&;
				inline auto SetValue(int pos, bool redraw = true) const -> const Trackbar&;
				inline auto Set(int min, int max, int value, bool redraw = true) const -> const Trackbar&;
				inline auto GetValue() const -> int;
			};

			class SizeText : public WindowBase<Trackbar, FszGroupBox::IDC + 3> 
			{
				friend FszGroupBox;
				using WindowBase::WindowBase;
			private:
				inline SizeText(HWND parent, HFONT font, HINSTANCE hInstance);
			public:
				inline auto SetValue(int value) const -> bool;
			};

		protected:

			static auto CALLBACK BoxProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) -> LRESULT;

		public:
			FszGroupBox::Editor const nameEditor;
			FszGroupBox::Trackbar const trackBar;
			FszGroupBox::SizeText const sizeText;
			FontManagerGUI* const manager;
			using WindowBase::WindowBase;

			inline FszGroupBox(FontManagerGUI* manager, HFONT font, HINSTANCE hInstance = ::GetModuleHandleW(NULL));
			~FszGroupBox() = default;
		};

		class StyGroupBox : public WindowBase<StyGroupBox, static_cast<uint16_t>(0x3000)> 
		{

			friend FontManagerGUI;
			using WindowBase::WindowBase;
			using WindowBase::operator=;

			template<typename T, uint16_t idc> class Button : public FontManagerGUI::ButtonBase<T, idc>
			{
				
				friend StyGroupBox;
				using FontManagerGUI::ButtonBase<T, idc>::ButtonBase;

				inline Button(LPCWSTR text, int X, int Y, HWND parent, HFONT font, HINSTANCE hInstance) :
					ButtonBase<T, idc>(text, WS_VISIBLE | WS_CHILD | BS_AUTORADIOBUTTON, 60, 25, X, Y, 
						parent, font, hInstance) {}

				inline auto Checked() const -> void 
				{
					this->SendMessage(BM_SETCHECK, BST_CHECKED, 0);
				}

				inline auto IsChecked() const -> bool 
				{
					return this->SendMessage(BM_GETCHECK, NULL, NULL);
				}

				inline auto UnChecked() const -> void
				{
					this->SendMessage(BM_SETCHECK, BST_UNCHECKED, 0);
				}
			};

			class Button1 : public Button<Button1, static_cast<uint16_t>(0xF000)>
			{
				friend StyGroupBox;

				inline Button1() : Button() {}
				inline Button1(HWND parent, HFONT font, HINSTANCE hInstance) :
					Button(L"常规", 25, 20, parent, font, hInstance) {
				}
			};

			class Button2 : public Button<Button2, static_cast<uint16_t>(0x00F0)> 
			{
				friend StyGroupBox;

				inline Button2() : Button() {}
				inline Button2(HWND parent, HFONT font, HINSTANCE hInstance) :
					Button(L"加粗", 25, 46, parent, font, hInstance) 
				{
				}
			};

			class Button3 : public Button<Button3, static_cast<uint16_t>(0xFF00)>
			{
				friend StyGroupBox;
				
				inline Button3() : Button() {}
				inline Button3(HWND parent, HFONT font, HINSTANCE hInstance) :
					Button(L"倾斜", 135, 20, parent, font, hInstance) {
				}
			};

			class Button4 : public Button<Button4, static_cast<uint16_t>(0x0FF0)>
			{
				friend StyGroupBox;
				
				inline Button4() : Button() {}
				inline Button4(HWND parent, HFONT font, HINSTANCE hInstance) :
					Button(L"斜粗", 135, 46, parent, font, hInstance) 
				{
				}
			};

		private:
			const Button1 button1;
			const Button2 button2;
			const Button3 button3;
			const Button4 button4;
		protected:
			FontManagerGUI* const manager;

			static auto CALLBACK BoxProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) -> LRESULT;

			inline StyGroupBox(FontManagerGUI* manager, HFONT font, HINSTANCE hInstance = ::GetModuleHandleW(NULL));
			~StyGroupBox() = default;

		public:
			inline auto GetChecked() const->uint16_t;
			auto SetChecked(uint16_t btn) const -> bool;
		};

		class ResetButton: public ButtonBase<StyGroupBox, static_cast<uint16_t>(0x4000)> 
		{
			friend FontManagerGUI;
			inline ResetButton(HWND parent, HFONT font, HINSTANCE hInstance): ButtonBase(
				L"默认值", WS_TABSTOP | WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON, 
				80, 28, 323, 280, parent, font, hInstance) {}
		};
		
		class ApplyButton: public ButtonBase<StyGroupBox, static_cast<uint16_t>(0x5000)>
		{
			friend FontManagerGUI;
			inline ApplyButton(HWND parent, HFONT font, HINSTANCE hInstance):ButtonBase(
				L"应　用", WS_TABSTOP | WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON,
				80, 28, 425, 280, parent, font, hInstance) {}
		};

		class ParentWindow : public WindowBase<ParentWindow, NULL> 
		{
			friend FontManagerGUI;
			using WindowBase::WindowBase;
		};

		class ActCtxHelper
		{
			friend FontManagerGUI;
		private:
			HANDLE m_ActCtx{ };
			ULONG_PTR m_Cookie{};
		public:
			auto Get() const -> HANDLE;
			auto Activate() -> bool;
			auto Deactivate() -> bool;
            ActCtxHelper();
			~ActCtxHelper();
		};

		friend FontListBox;
		friend FszGroupBox;
		friend StyGroupBox;

	public:
		
		enum Style : uint16_t
		{ 
			NORMAL = StyGroupBox::Button1::IDC,
			BOLD   = StyGroupBox::Button2::IDC,
			ITALIC = StyGroupBox::Button3::IDC,
			BOLD_ITALIC = StyGroupBox::Button4::IDC
		};
		
		struct Data { int16_t size; Style style; wchar_t name[32] = L""; };
		using Callback = std::function<void(const FontManagerGUI* m_this)>;

	private:

		static auto CALLBACK ManagerWndProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) -> LRESULT;

		static auto Init(INITCOMMONCONTROLSEX icc = { sizeof(INITCOMMONCONTROLSEX), ICC_STANDARD_CLASSES },
			WNDCLASSEX cls = { sizeof(WNDCLASSEX), CS_SAVEBITS }) -> void;

	protected:

		static inline constexpr wchar_t ManagerClassName[] = L"FontManagerGUI";
		static inline constexpr auto DefaultBackgroundColor{ RGB(232, 234, 240) };
		static inline const auto DefaultSolidBrush{ ::CreateSolidBrush(FontManagerGUI::DefaultBackgroundColor) };
        static inline const auto VisStyActCtx{ std::make_unique<ActCtxHelper>() };

		const HFONT m_hFont;
		const StyGroupBox m_StyGroupBox;
		const FszGroupBox m_FszGroupBox;
		const FontListBox m_FontListBox;
		const ApplyButton m_ApplyButton;
		const ResetButton m_ResetButton;
		const ParentWindow m_Parent;

		std::string m_storageFilePath{};
		FontManagerGUI::Callback m_Callback{};
		bool m_OnChoosing{ false }, m_DataUpdate{ false };
		FontManagerGUI::Data defaultData{}, currentData{}, lastData{};

		FontManagerGUI(HWND parent, HFONT font, HINSTANCE hInstance = ::GetModuleHandleW(NULL));
		auto InitDisplay(SIZE size = {}, PAINTSTRUCT ps = {}) -> FontManagerGUI&;
		auto UpdateDisplay(bool state = false) -> FontManagerGUI&;
		auto UpdateBoxState() -> FontManagerGUI&;
		auto ShowWindow(bool topMost = false) const -> BOOL;
		auto IsFullScreen() const -> bool;
        auto OnChanged() -> void;
	public:

		auto MessageLoop() const -> void;
		auto MakeFont(DWORD iCharSet = ANSI_CHARSET, int baseSize = 0) const->HFONT;
		auto MakeDefualtFont(DWORD iCharSet = ANSI_CHARSET, int baseSize = 0) const->HFONT;
		auto Load(Data currentData) -> FontManagerGUI&;
		auto Load(int size, Style style, std::wstring_view name) -> FontManagerGUI&;
		auto Load(std::string_view storageFilePath, bool init = true) -> FontManagerGUI&;
		auto Init(Data defaultData, int minSize = 18, int maxSize = 35) -> FontManagerGUI&;
		auto Init(int size, Style style, std::wstring_view name, int minSize = 18, int maxSize = 35) -> FontManagerGUI&;
		auto OnChanged(Callback callback) -> FontManagerGUI&;
		auto OnChanged(std::function<void(int32_t size, Style style, const std::wstring_view name)> callback) -> FontManagerGUI&;
		auto StorageData(std::string_view storageFilePath) const -> bool;
		auto StorageData() const -> bool;
		auto GetData() const -> const Data&;
		auto ChooseFont() -> FontManagerGUI&;
		auto ChooseFont(std::function<void(int32_t size, Style style, const std::wstring_view name)> callback) -> FontManagerGUI&;
		auto Wait() -> FontManagerGUI&;
		auto IsWindowVisible() -> bool;
		auto UpdateDisplayState() -> FontManagerGUI&;
        auto HideWindow() const->BOOL;

		static auto CreatePtr(HWND parent, HFONT hFont, HINSTANCE hInstance = ::GetModuleHandleW(NULL)) -> std::unique_ptr<FontManagerGUI>;
		static auto CreatePtr(HFONT hFont, HINSTANCE hInstance = ::GetModuleHandleW(NULL)) -> std::unique_ptr<FontManagerGUI>;
		static auto CreatePtr(HWND parent, HINSTANCE hInstance = ::GetModuleHandleW(NULL)) -> std::unique_ptr<FontManagerGUI>;
	};

}
