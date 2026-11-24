#include "app.h"
#include "util.h"

#include <windows.h>
#include <commctrl.h>
#include <dwmapi.h>
#include <shellapi.h>
#include <uxtheme.h>
#include <windowsx.h>

#include <cstdint>
#include <cstdio>
#include <iterator>
#include <string>
#include <unordered_map>

namespace {

/* ------------------------------------------------------------------ */
/* Palette                                                             */
/* ------------------------------------------------------------------ */

constexpr COLORREF kBg = RGB(9, 6, 14);
constexpr COLORREF kPanel = RGB(20, 13, 31);
constexpr COLORREF kPanelHover = RGB(30, 20, 46);
constexpr COLORREF kPanelPress = RGB(38, 25, 58);
constexpr COLORREF kPanelOff = RGB(16, 11, 24);
constexpr COLORREF kAccent = RGB(124, 58, 237);
constexpr COLORREF kAccentHover = RGB(139, 92, 246);
constexpr COLORREF kAccentPress = RGB(104, 45, 205);
constexpr COLORREF kAccentEdge = RGB(167, 139, 250);
constexpr COLORREF kBorder = RGB(47, 31, 70);
constexpr COLORREF kBorderHover = RGB(90, 60, 132);
constexpr COLORREF kText = RGB(236, 229, 248);
constexpr COLORREF kTextDim = RGB(160, 141, 190);
constexpr COLORREF kTextOff = RGB(96, 84, 116);
constexpr COLORREF kOk = RGB(74, 222, 128);
constexpr COLORREF kWarn = RGB(250, 190, 70);
constexpr COLORREF kErr = RGB(255, 92, 122);

/* ------------------------------------------------------------------ */
/* Ids and window handles                                              */
/* ------------------------------------------------------------------ */

constexpr wchar_t kWindowClass[] = L"HwidSpoofUi";
constexpr wchar_t kWindowTitle[] = L"HWID Spoofer";

constexpr int kIdSeed = 1000;
constexpr int kIdSkipDriver = 1001;
constexpr int kIdSkipRegistry = 1002;
constexpr int kIdSkipNetwork = 1003;
constexpr int kIdDryRun = 1004;
/* Last of the tick boxes: contiguous ids are how the state array is indexed. */
constexpr int kIdReveal = 1005;
constexpr int kIdSpoof = 1010;
constexpr int kIdInstall = 1011;
constexpr int kIdReapply = 1012;
constexpr int kIdVerify = 1013;
constexpr int kIdStatus = 1014;
constexpr int kIdRestore = 1015;
constexpr int kIdUninstall = 1016;
constexpr int kIdElevate = 1017;
constexpr int kIdRestart = 1018;
constexpr int kIdLog = 1020;

constexpr UINT kMsgDone = WM_APP + 1;

HWND g_window = nullptr;
HWND g_title = nullptr;
HWND g_subtitle = nullptr;
HWND g_kernelBadge = nullptr;
HWND g_seedLabel = nullptr;
HWND g_seed = nullptr;
HWND g_log = nullptr;
HWND g_status = nullptr;
HWND g_skipDriver = nullptr;
HWND g_skipRegistry = nullptr;
HWND g_skipNetwork = nullptr;
HWND g_dryRun = nullptr;
HWND g_reveal = nullptr;
HWND g_elevate = nullptr;
HWND g_buttons[8]{};

HBRUSH g_bgBrush = nullptr;
HBRUSH g_panelBrush = nullptr;
HFONT g_titleFont = nullptr;
HFONT g_uiFont = nullptr;
HFONT g_smallFont = nullptr;
HFONT g_logFont = nullptr;

HANDLE g_thread = nullptr;
bool g_running = false;
bool g_elevated = false;
app::Mode g_lastMode = app::Mode::None;
app::Options g_base;
std::unordered_map<HWND, bool> g_hover;

/* ------------------------------------------------------------------ */
/* Helpers                                                             */
/* ------------------------------------------------------------------ */

int Scale(int value)
{
    static const int factor = []
    {
        const HDC screen = GetDC(nullptr);
        const int dpi = screen != nullptr ? GetDeviceCaps(screen, LOGPIXELSX) : 96;
        if (screen != nullptr) {
            ReleaseDC(nullptr, screen);
        }
        return dpi <= 0 ? 100 : (dpi * 100) / 96;
    }();
    return (value * factor) / 100;
}

void SetStatus(const std::wstring& text, COLORREF colour)
{
    if (g_status == nullptr) {
        return;
    }
    SetWindowTextW(g_status, text.c_str());
    InvalidateRect(g_status, nullptr, TRUE);
    /* The colour is looked up by handle in WM_CTLCOLORSTATIC. */
    SetPropW(g_status, L"colour", reinterpret_cast<HANDLE>(static_cast<INT_PTR>(colour)));
}

void AppendLog(const std::wstring& line)
{
    if (g_log == nullptr) {
        return;
    }
    if (GetWindowTextLengthW(g_log) > 400000) {
        SetWindowTextW(g_log, L"");
    }
    const int length = GetWindowTextLengthW(g_log);
    const std::wstring text = line + L"\r\n";
    SendMessageW(g_log, EM_SETSEL, static_cast<WPARAM>(length), static_cast<LPARAM>(length));
    SendMessageW(g_log, EM_REPLACESEL, FALSE, reinterpret_cast<LPARAM>(text.c_str()));
}

COLORREF StatusColour()
{
    const HANDLE value = GetPropW(g_status, L"colour");
    return static_cast<COLORREF>(reinterpret_cast<INT_PTR>(value));
}

COLORREF BadgeColour()
{
    const HANDLE value = GetPropW(g_kernelBadge, L"colour");
    return static_cast<COLORREF>(reinterpret_cast<INT_PTR>(value));
}

/*
 * Re-read boot policy and the on-disk image. Cheap enough to run after every
 * job, and it keeps the badge honest when a driver was signed or replaced
 * while the window was open.
 */
void RefreshKernel()
{
    if (g_kernelBadge == nullptr) {
        return;
    }

    const app::KernelGate gate = app::InspectKernel(g_base.driverPath);
    SetWindowTextW(g_kernelBadge, gate.summary.c_str());

    COLORREF colour = kTextDim;
    if (gate.canStart) {
        colour = kOk;
    } else if (gate.signerValid) {
        colour = kWarn;
    }
    SetPropW(g_kernelBadge, L"colour",
             reinterpret_cast<HANDLE>(static_cast<INT_PTR>(colour)));
    InvalidateRect(g_kernelBadge, nullptr, TRUE);
}

HWND MakeButton(HWND parent, int id, const wchar_t* text, int x, int y, int w, int h)
{
    const HWND control = CreateWindowExW(
        0, L"BUTTON", text, WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_OWNERDRAW, Scale(x),
        Scale(y), Scale(w), Scale(h), parent, reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)),
        nullptr, nullptr);
    SendMessageW(control, WM_SETFONT, reinterpret_cast<WPARAM>(g_uiFont), TRUE);
    return control;
}

HWND MakeCheck(HWND parent, int id, const wchar_t* text, int x, int y, int w)
{
    const HWND control = CreateWindowExW(
        0, L"BUTTON", text, WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_OWNERDRAW,
        Scale(x), Scale(y), Scale(w), Scale(26), parent,
        reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)), nullptr, nullptr);
    SendMessageW(control, WM_SETFONT, reinterpret_cast<WPARAM>(g_uiFont), TRUE);
    return control;
}

/*
 * BS_OWNERDRAW replaces the button type, so BS_AUTOCHECKBOX does nothing.
 * The tick state is ours; the ids below are contiguous on purpose.
 */
bool g_checkState[5] = {false, false, false, false, false};

bool IsCheckId(int id)
{
    return id >= kIdSkipDriver && id <= kIdReveal;
}

int CheckSlot(int id)
{
    return id - kIdSkipDriver;
}

bool CheckState(int id)
{
    const int slot = CheckSlot(id);
    return slot >= 0 && slot < static_cast<int>(std::size(g_checkState)) &&
           g_checkState[slot];
}

void ToggleCheck(int id)
{
    const int slot = CheckSlot(id);
    if (slot >= 0 && slot < static_cast<int>(std::size(g_checkState))) {
        g_checkState[slot] = !g_checkState[slot];
    }
}

/* ------------------------------------------------------------------ */
/* Ownerdraw                                                           */
/* ------------------------------------------------------------------ */

bool IsPrimary(int id)
{
    return id == kIdSpoof || id == kIdInstall;
}

void FillRectColour(HDC dc, const RECT& rect, COLORREF colour)
{
    const HBRUSH brush = CreateSolidBrush(colour);
    FillRect(dc, &rect, brush);
    DeleteObject(brush);
}

void DrawActionButton(const DRAWITEMSTRUCT* item)
{
    const bool disabled = (item->itemState & ODS_DISABLED) != 0;
    const bool pressed = (item->itemState & ODS_SELECTED) != 0;
    const bool hovered = g_hover[item->hwndItem];
    const bool primary = IsPrimary(item->CtlID);

    RECT rect = item->rcItem;
    FillRectColour(item->hDC, rect, kBg);

    COLORREF fill;
    COLORREF edge;
    COLORREF text;
    if (disabled) {
        fill = kPanelOff;
        edge = kBorder;
        text = kTextOff;
    } else if (primary) {
        fill = pressed ? kAccentPress : (hovered ? kAccentHover : kAccent);
        edge = kAccentEdge;
        text = RGB(255, 255, 255);
    } else {
        fill = pressed ? kPanelPress : (hovered ? kPanelHover : kPanel);
        edge = hovered ? kBorderHover : kBorder;
        text = kText;
    }

    const HBRUSH brush = CreateSolidBrush(fill);
    const HPEN pen = CreatePen(PS_SOLID, 1, edge);
    const HGDIOBJ oldBrush = SelectObject(item->hDC, brush);
    const HGDIOBJ oldPen = SelectObject(item->hDC, pen);
    RoundRect(item->hDC, rect.left, rect.top, rect.right, rect.bottom, Scale(10), Scale(10));
    SelectObject(item->hDC, oldBrush);
    SelectObject(item->hDC, oldPen);
    DeleteObject(brush);
    DeleteObject(pen);

    wchar_t label[128]{};
    GetWindowTextW(item->hwndItem, label, static_cast<int>(std::size(label)));

    SetBkMode(item->hDC, TRANSPARENT);
    SetTextColor(item->hDC, text);
    DrawTextW(item->hDC, label, -1, &rect, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
}

void DrawCheckBox(const DRAWITEMSTRUCT* item)
{
    const bool disabled = (item->itemState & ODS_DISABLED) != 0;
    const bool pressed = (item->itemState & ODS_SELECTED) != 0;
    const bool hovered = g_hover[item->hwndItem];
    const bool checked = CheckState(item->CtlID);

    RECT rect = item->rcItem;
    FillRectColour(item->hDC, rect, kBg);

    const int box = Scale(17);
    RECT boxRect{rect.left, rect.top + (rect.bottom - rect.top - box) / 2,
                 rect.left + box, rect.top + (rect.bottom - rect.top - box) / 2 + box};

    COLORREF fill = checked ? (pressed ? kAccentPress : (hovered ? kAccentHover : kAccent))
                            : (hovered ? kPanelHover : kPanelOff);
    if (disabled) {
        fill = kPanelOff;
    }
    const HBRUSH brush = CreateSolidBrush(fill);
    const HPEN pen = CreatePen(PS_SOLID, 1,
                               disabled ? kBorder : (checked ? kAccentEdge
                                                             : (hovered ? kBorderHover : kBorder)));
    const HGDIOBJ oldBrush = SelectObject(item->hDC, brush);
    const HGDIOBJ oldPen = SelectObject(item->hDC, pen);
    RoundRect(item->hDC, boxRect.left, boxRect.top, boxRect.right, boxRect.bottom, Scale(5),
              Scale(5));
    SelectObject(item->hDC, oldBrush);
    SelectObject(item->hDC, oldPen);
    DeleteObject(brush);
    DeleteObject(pen);

    if (checked) {
        const HPEN tick = CreatePen(PS_SOLID, Scale(2), RGB(255, 255, 255));
        const HGDIOBJ oldPen2 = SelectObject(item->hDC, tick);
        const int cx = boxRect.left + box / 2;
        const int cy = boxRect.top + box / 2;
        MoveToEx(item->hDC, cx - Scale(4), cy, nullptr);
        LineTo(item->hDC, cx - Scale(1), cy + Scale(3));
        LineTo(item->hDC, cx + Scale(5), cy - Scale(4));
        SelectObject(item->hDC, oldPen2);
        DeleteObject(tick);
    }

    wchar_t label[128]{};
    GetWindowTextW(item->hwndItem, label, static_cast<int>(std::size(label)));

    RECT textRect = rect;
    textRect.left = boxRect.right + Scale(8);
    SetBkMode(item->hDC, TRANSPARENT);
    SetTextColor(item->hDC, disabled ? kTextOff : (hovered ? kText : kTextDim));
    DrawTextW(item->hDC, label, -1, &textRect, DT_LEFT | DT_VCENTER | DT_SINGLELINE);
}

LRESULT CALLBACK ButtonSubclass(HWND window, UINT message, WPARAM wparam, LPARAM lparam,
                                UINT_PTR subclassId, DWORD_PTR data)
{
    UNREFERENCED_PARAMETER(subclassId);
    UNREFERENCED_PARAMETER(data);

    switch (message) {
    case WM_MOUSEMOVE:
        if (!g_hover[window]) {
            g_hover[window] = true;
            InvalidateRect(window, nullptr, TRUE);
            TRACKMOUSEEVENT track{sizeof(track), TME_LEAVE, window, 0};
            TrackMouseEvent(&track);
        }
        break;
    case WM_MOUSELEAVE:
        g_hover[window] = false;
        InvalidateRect(window, nullptr, TRUE);
        break;
    default:
        break;
    }
    return DefSubclassProc(window, message, wparam, lparam);
}

/* ------------------------------------------------------------------ */
/* Job plumbing                                                        */
/* ------------------------------------------------------------------ */

void SetBusy(bool busy)
{
    for (HWND button : g_buttons) {
        if (button != nullptr) {
            EnableWindow(button, busy ? FALSE : TRUE);
            InvalidateRect(button, nullptr, TRUE);
        }
    }
    if (g_elevate != nullptr) {
        EnableWindow(g_elevate, (busy || g_elevated) ? FALSE : TRUE);
        InvalidateRect(g_elevate, nullptr, TRUE);
    }
    EnableWindow(g_seed, busy ? FALSE : TRUE);
    EnableWindow(g_skipDriver, busy ? FALSE : TRUE);
    EnableWindow(g_skipRegistry, busy ? FALSE : TRUE);
    EnableWindow(g_skipNetwork, busy ? FALSE : TRUE);
    EnableWindow(g_dryRun, busy ? FALSE : TRUE);
    EnableWindow(g_reveal, busy ? FALSE : TRUE);
}

bool ReadSeed(uint64_t& seed, std::wstring& error)
{
    const int length = GetWindowTextLengthW(g_seed);
    if (length == 0) {
        seed = 0;
        return true;
    }
    std::wstring text(static_cast<size_t>(length) + 1, L'\0');
    GetWindowTextW(g_seed, text.data(), length + 1);
    text.resize(static_cast<size_t>(length));
    if (!app::ParseSeed(text, seed)) {
        error = L"The seed must be a non-zero decimal or 0x-prefixed hex value.";
        return false;
    }
    return true;
}

DWORD WINAPI JobThread(LPVOID parameter)
{
    app::Options* options = static_cast<app::Options*>(parameter);
    const int code = app::Run(*options);
    delete options;
    PostMessageW(g_window, kMsgDone, static_cast<WPARAM>(code), 0);
    return 0;
}

void StartJob(app::Mode mode)
{
    if (g_running) {
        return;
    }
    if (!g_elevated) {
        MessageBoxW(g_window, L"Administrator rights are required for this action.",
                    kWindowTitle, MB_ICONWARNING | MB_OK);
        return;
    }

    uint64_t seed = 0;
    std::wstring error;
    if (!ReadSeed(seed, error)) {
        MessageBoxW(g_window, error.c_str(), kWindowTitle, MB_ICONWARNING | MB_OK);
        return;
    }

    app::Options* options = new app::Options(g_base);
    options->mode = mode;
    options->seed = seed;
    options->perma = (mode == app::Mode::Install) || g_base.perma;
    options->noDriver = CheckState(kIdSkipDriver);
    options->noRegistry = CheckState(kIdSkipRegistry);
    options->noNetwork = CheckState(kIdSkipNetwork);
    options->dryRun = CheckState(kIdDryRun);
    options->reveal = CheckState(kIdReveal);
    options->verbose = true;
    if (mode == app::Mode::Reapply) {
        options->keepProfile = true;
    }

    SetBusy(true);
    SetStatus(L"Working...", kWarn);
    g_running = true;
    g_lastMode = mode;
    AppendLog(L"");
    g_thread = CreateThread(nullptr, 0, JobThread, options, 0, nullptr);
    if (g_thread == nullptr) {
        delete options;
        g_running = false;
        SetBusy(false);
        SetStatus(L"Cannot start the worker thread.", kErr);
        return;
    }
}

const wchar_t* DoneMessage(app::Mode mode)
{
    switch (mode) {
    case app::Mode::Spoof:
    case app::Mode::Install:
        return L"Done - reboot so every consumer sees the new identity";
    case app::Mode::Reapply:
        return L"Done - reboot if any value still reads the old one";
    case app::Mode::Verify:
        return L"Verify finished - read the log for mismatches";
    case app::Mode::Status:
        return L"Status read - kernel state is in the badge and the log";
    case app::Mode::Restore:
        return CheckState(kIdReveal)
                   ? L"Originals restored - printed in clear, reveal is on"
                   : L"Originals restored - masked in the log, reboot to retire cached copies";
    case app::Mode::Uninstall:
        return L"Uninstalled - service and image removed";
    default:
        return L"Done";
    }
}

void FinishJob(int exitCode)
{
    if (g_thread != nullptr) {
        WaitForSingleObject(g_thread, 5000);
        CloseHandle(g_thread);
        g_thread = nullptr;
    }
    g_running = false;
    SetBusy(false);
    RefreshKernel();

    if (exitCode == 0) {
        SetStatus(DoneMessage(g_lastMode), kOk);
        return;
    }

    /*
     * The engine already knows which component failed. Naming it here beats
     * "see the log": the user gets the answer without opening anything.
     */
    std::wstring detail;
    for (const std::wstring& issue : app::LastIssues()) {
        if (!detail.empty()) {
            detail += L", ";
        }
        detail += issue;
    }
    if (detail.empty()) {
        detail = L"see the log";
    }
    SetStatus(L"Finished - " + detail, kErr);
}

/* ------------------------------------------------------------------ */
/* Dark mode opt-in                                                    */
/* ------------------------------------------------------------------ */

/*
 * Uxtheme's dark mode is undocumented but stable since 1809: ordinal 135
 * sets the app preference, 133 opts a window in. Without it the edit
 * scrollbars and the client edge stay light and the theme looks half done.
 */
void EnableDarkMode(HWND window)
{
    const HMODULE uxtheme = GetModuleHandleW(L"uxtheme.dll");
    if (uxtheme != nullptr) {
        using SetPreferredAppModeFn = int(WINAPI*)(int);
        using AllowDarkModeFn = BOOL(WINAPI*)(HWND, BOOL);

        const auto setMode = reinterpret_cast<SetPreferredAppModeFn>(
            GetProcAddress(uxtheme, reinterpret_cast<LPCSTR>(135)));
        const auto allow = reinterpret_cast<AllowDarkModeFn>(
            GetProcAddress(uxtheme, reinterpret_cast<LPCSTR>(133)));
        if (setMode != nullptr) {
            (VOID)setMode(1);
        }
        if (allow != nullptr) {
            (VOID)allow(window, TRUE);
        }
    }
    (VOID)SetWindowTheme(window, L"DarkMode_Explorer", nullptr);
}

/* ------------------------------------------------------------------ */
/* Icon                                                                */
/* ------------------------------------------------------------------ */

/*
 * A generated badge beats IDI_APPLICATION: the shipped build has no .rc and
 * therefore no icon resource, so without this the taskbar shows Windows'
 * generic white window.
 */
HICON MakeAppIcon()
{
    constexpr int size = 32;

    BITMAPV5HEADER header{};
    header.bV5Size = sizeof(header);
    header.bV5Width = size;
    header.bV5Height = -size;
    header.bV5Planes = 1;
    header.bV5BitCount = 32;
    header.bV5Compression = BI_BITFIELDS;
    header.bV5RedMask = 0x00FF0000;
    header.bV5GreenMask = 0x0000FF00;
    header.bV5BlueMask = 0x000000FF;
    header.bV5AlphaMask = 0xFF000000;

    void* bits = nullptr;
    const HDC screen = GetDC(nullptr);
    const HBITMAP colour = CreateDIBSection(screen, reinterpret_cast<BITMAPINFO*>(&header),
                                            DIB_RGB_COLORS, &bits, nullptr, 0);
    ReleaseDC(nullptr, screen);
    if (colour == nullptr || bits == nullptr) {
        return LoadIconW(nullptr, IDI_APPLICATION);
    }

    const HDC dc = CreateCompatibleDC(nullptr);
    const HGDIOBJ oldBitmap = SelectObject(dc, colour);

    RECT full{0, 0, size, size};
    HBRUSH fill = CreateSolidBrush(kAccent);
    FillRect(dc, &full, fill);
    DeleteObject(fill);

    RECT stripe{0, 0, size, 4};
    fill = CreateSolidBrush(kAccentEdge);
    FillRect(dc, &stripe, fill);
    DeleteObject(fill);

    const HFONT font = CreateFontW(-22, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE, DEFAULT_CHARSET,
                                   OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
                                   DEFAULT_PITCH, L"Segoe UI");
    const HGDIOBJ oldFont = SelectObject(dc, font);
    SetBkMode(dc, TRANSPARENT);
    SetTextColor(dc, kBg);
    DrawTextW(dc, L"H", -1, &full, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
    SelectObject(dc, oldFont);
    DeleteObject(font);

    SelectObject(dc, oldBitmap);
    DeleteDC(dc);

    /* GDI leaves alpha at zero; the badge is meant to be opaque. */
    auto* pixels = static_cast<uint32_t*>(bits);
    for (int index = 0; index < size * size; index++) {
        pixels[index] |= 0xFF000000u;
    }

    const HBITMAP mask = CreateBitmap(size, size, 1, 1, nullptr);
    ICONINFO info{};
    info.fIcon = TRUE;
    info.hbmMask = mask;
    info.hbmColor = colour;
    const HICON icon = CreateIconIndirect(&info);
    DeleteObject(colour);
    DeleteObject(mask);
    return icon != nullptr ? icon : LoadIconW(nullptr, IDI_APPLICATION);
}

/* ------------------------------------------------------------------ */
/* Window construction                                                 */
/* ------------------------------------------------------------------ */

void CreateFonts()
{
    g_titleFont = CreateFontW(-Scale(24), 0, 0, 0, FW_SEMIBOLD, FALSE, FALSE, FALSE,
                              DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                              CLEARTYPE_QUALITY, DEFAULT_PITCH, L"Segoe UI");
    g_uiFont = CreateFontW(-Scale(15), 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET,
                           OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
                           DEFAULT_PITCH, L"Segoe UI");
    g_smallFont = CreateFontW(-Scale(12), 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                              DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                              CLEARTYPE_QUALITY, DEFAULT_PITCH, L"Segoe UI");
    g_logFont = CreateFontW(-Scale(13), 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET,
                            OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
                            FIXED_PITCH, L"Consolas");
}

void CreateControls(HWND window)
{
    CreateFonts();
    g_bgBrush = CreateSolidBrush(kBg);
    g_panelBrush = CreateSolidBrush(kPanel);

    g_title = CreateWindowExW(0, L"STATIC", L"HWID SPOOFER", WS_CHILD | WS_VISIBLE, Scale(24),
                              Scale(14), Scale(420), Scale(36), window, nullptr, nullptr, nullptr);
    SendMessageW(g_title, WM_SETFONT, reinterpret_cast<WPARAM>(g_titleFont), TRUE);

    g_subtitle = CreateWindowExW(0, L"STATIC",
                                 L"kernel-assisted identity replacement \xB7 perma arming",
                                 WS_CHILD | WS_VISIBLE, Scale(26), Scale(50), Scale(520),
                                 Scale(22), window, nullptr, nullptr, nullptr);
    SendMessageW(g_subtitle, WM_SETFONT, reinterpret_cast<WPARAM>(g_smallFont), TRUE);

    /*
     * Boot-policy state belongs next to the version, not buried in the log:
     * it decides whether firmware, disk and volume surfaces can be touched
     * at all, and it is the first thing worth knowing on a new machine.
     */
    g_kernelBadge = CreateWindowExW(0, L"STATIC", L"",
                                    WS_CHILD | WS_VISIBLE | SS_RIGHT, Scale(420), Scale(16),
                                    Scale(310), Scale(20), window, nullptr, nullptr, nullptr);
    SendMessageW(g_kernelBadge, WM_SETFONT, reinterpret_cast<WPARAM>(g_smallFont), TRUE);

    const HWND seedLabel = CreateWindowExW(0, L"STATIC", L"SEED  \xB7  OPTIONAL", WS_CHILD | WS_VISIBLE,
                                           Scale(24), Scale(88), Scale(220), Scale(18), window,
                                           nullptr, nullptr, nullptr);
    SendMessageW(seedLabel, WM_SETFONT, reinterpret_cast<WPARAM>(g_smallFont), TRUE);
    g_seedLabel = seedLabel;

    g_seed = CreateWindowExW(0, L"EDIT", L"",
                             WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL, Scale(30),
                             Scale(113), Scale(288), Scale(26), window,
                             reinterpret_cast<HMENU>(static_cast<INT_PTR>(kIdSeed)), nullptr,
                             nullptr);
    SendMessageW(g_seed, WM_SETFONT, reinterpret_cast<WPARAM>(g_uiFont), TRUE);
    SendMessageW(g_seed, EM_SETMARGINS, EC_LEFTMARGIN | EC_RIGHTMARGIN,
                 MAKELPARAM(Scale(6), Scale(6)));

    g_skipDriver = MakeCheck(window, kIdSkipDriver, L"skip driver", 344, 112, 100);
    g_skipRegistry = MakeCheck(window, kIdSkipRegistry, L"skip registry", 452, 112, 112);
    g_skipNetwork = MakeCheck(window, kIdSkipNetwork, L"skip network", 572, 112, 104);
    g_dryRun = MakeCheck(window, kIdDryRun, L"dry run", 684, 112, 76);
    /* Reveal is the one tick that changes what the log says, not what the tool
       does. It sits with the other ticks because that is where it will be
       looked for, and it is off on every start. */
    g_reveal = MakeCheck(window, kIdReveal, L"reveal reals", 766, 112, 110);

    g_buttons[0] = MakeButton(window, kIdSpoof, L"Spoof now", 24, 160, 160, 42);
    g_buttons[1] = MakeButton(window, kIdInstall, L"Install perma", 192, 160, 180, 42);
    g_buttons[2] = MakeButton(window, kIdReapply, L"Reapply", 380, 160, 128, 42);
    g_buttons[3] = MakeButton(window, kIdVerify, L"Verify", 516, 160, 110, 42);

    g_buttons[4] = MakeButton(window, kIdStatus, L"Status", 24, 212, 128, 38);
    g_buttons[5] = MakeButton(window, kIdRestore, L"Reverse spoof", 160, 212, 176, 38);
    g_buttons[6] = MakeButton(window, kIdRestart, L"Restart PC", 344, 212, 140, 38);
    g_buttons[7] = MakeButton(window, kIdUninstall, L"Uninstall", 492, 212, 140, 38);

    if (!g_elevated) {
        g_elevate = MakeButton(window, kIdElevate, L"Restart as admin", 644, 212, 190, 38);
    }

    g_log = CreateWindowExW(
        0, L"EDIT", L"",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_VSCROLL | ES_MULTILINE | ES_READONLY |
            ES_AUTOVSCROLL,
        Scale(26), Scale(278), Scale(848), Scale(308), window,
        reinterpret_cast<HMENU>(static_cast<INT_PTR>(kIdLog)), nullptr, nullptr);
    SendMessageW(g_log, WM_SETFONT, reinterpret_cast<WPARAM>(g_logFont), TRUE);
    SendMessageW(g_log, EM_SETMARGINS, EC_LEFTMARGIN | EC_RIGHTMARGIN,
                 MAKELPARAM(Scale(8), Scale(8)));
    (VOID)SetWindowTheme(g_log, L"DarkMode_Explorer", nullptr);

    g_status = CreateWindowExW(0, L"STATIC", L"Starting...", WS_CHILD | WS_VISIBLE, Scale(26),
                               Scale(600), Scale(700), Scale(22), window, nullptr, nullptr,
                               nullptr);
    SendMessageW(g_status, WM_SETFONT, reinterpret_cast<WPARAM>(g_smallFont), TRUE);

    const std::wstring versionText = std::wstring(L"v") + app::kVersion;
    const HWND version = CreateWindowExW(0, L"STATIC", versionText.c_str(),
                                         WS_CHILD | WS_VISIBLE, Scale(742), Scale(18),
                                         Scale(130), Scale(20), window, nullptr, nullptr,
                                         nullptr);
    SendMessageW(version, WM_SETFONT, reinterpret_cast<WPARAM>(g_smallFont), TRUE);
    SetStatus(L"Idle", kTextDim);
    RefreshKernel();

    EnableDarkMode(window);
    EnableDarkMode(g_log);
    EnableDarkMode(g_seed);

    for (HWND button : g_buttons) {
        SetWindowSubclass(button, ButtonSubclass, 1, 0);
    }
    if (g_elevate != nullptr) {
        SetWindowSubclass(g_elevate, ButtonSubclass, 1, 0);
    }
    for (HWND check : {g_skipDriver, g_skipRegistry, g_skipNetwork, g_dryRun, g_reveal}) {
        SetWindowSubclass(check, ButtonSubclass, 1, 0);
    }

    AppendLog(L"HWID Spoofer " + std::wstring(app::kVersion));
    AppendLog(L"");
    AppendLog(L"Spoof now      new identity, driver on demand, everything applied");
    AppendLog(L"Install perma  new identity, driver at every boot, config stored");
    AppendLog(L"Reapply        push the stored profile again");
    AppendLog(L"Verify         read every surface back and compare");
    AppendLog(L"Status         driver filters, SMBIOS state, persisted flag");
    AppendLog(L"Reverse spoof  put the real values back, masked in the log");
    AppendLog(L"Restart PC     reboot so registry, hostname and volumes settle");
    AppendLog(L"Uninstall      restore, delete the config, remove the service");
    AppendLog(L"");
    AppendLog(L"real values are masked in this log; only profile values print in clear");
    AppendLog(L"tick \"reveal reals\" before a job to print them in clear instead");

    app::Options probe;
    app::ApplyDefaults(probe);
    if (!util::FileExists(probe.driverPath)) {
        AppendLog(L"driver file missing: " + probe.driverPath);
        AppendLog(L"build it with build.ps1 and a WDK, then sign it");
    } else {
        AppendLog(L"driver file: " + probe.driverPath);
    }

    const app::KernelGate gate = app::InspectKernel(probe.driverPath);
    AppendLog(std::wstring(L"platform: Secure Boot ") + (gate.secureBoot ? L"on" : L"off") +
              L", test signing " + (gate.testSigning ? L"on" : L"off") +
              L", memory integrity " + (gate.hvci ? L"on" : L"off"));
    if (!gate.signer.empty()) {
        AppendLog(L"driver signed by: " + gate.signer);
    }
    if (!gate.canStart) {
        AppendLog(L"kernel surfaces unavailable: " + gate.blocker);
        AppendLog(L"registry, hostname and network surfaces apply without the driver");
        if (gate.secureBoot) {
            AppendLog(L"Secure Boot is left on; no boot setting is changed by this tool");
        }
    }

    if (!g_elevated) {
        AppendLog(L"running unelevated: actions are disabled until you restart as admin");
    }
}

void PaintChrome(HWND window)
{
    PAINTSTRUCT paint{};
    const HDC dc = BeginPaint(window, &paint);

    RECT client{};
    GetClientRect(window, &client);
    FillRect(dc, &client, g_bgBrush);

    /* Accent rule under the header. */
    RECT rule{0, 0, client.right, Scale(3)};
    RECT headerRule{Scale(24), Scale(80), client.right - Scale(24), Scale(81)};
    FillRectColour(dc, rule, kAccent);
    FillRectColour(dc, headerRule, kBorder);

    /* Frame behind the log pane. */
    RECT frame{Scale(20), Scale(270), client.right - Scale(20), Scale(594)};
    const HBRUSH panel = CreateSolidBrush(kPanel);
    const HPEN pen = CreatePen(PS_SOLID, 1, kBorder);
    const HGDIOBJ oldBrush = SelectObject(dc, panel);
    const HGDIOBJ oldPen = SelectObject(dc, pen);
    RoundRect(dc, frame.left, frame.top, frame.right, frame.bottom, Scale(12), Scale(12));

    /* Frame behind the seed field, same language as the log. */
    RECT input{Scale(24), Scale(106), Scale(324), Scale(142)};
    const HBRUSH inputFill = CreateSolidBrush(RGB(14, 9, 22));
    SelectObject(dc, inputFill);
    RoundRect(dc, input.left, input.top, input.right, input.bottom, Scale(8), Scale(8));
    DeleteObject(inputFill);

    SelectObject(dc, oldBrush);
    SelectObject(dc, oldPen);
    DeleteObject(panel);
    DeleteObject(pen);

    /* Status strip line. */
    RECT strip{Scale(24), Scale(596), client.right - Scale(24), Scale(597)};
    FillRectColour(dc, strip, kBorder);

    EndPaint(window, &paint);
}

LRESULT OnCtlColour(UINT message, WPARAM wparam, LPARAM lparam)
{
    const HDC dc = reinterpret_cast<HDC>(wparam);
    const HWND control = reinterpret_cast<HWND>(lparam);
    SetBkMode(dc, OPAQUE);
    SetBkColor(dc, kPanel);
    SetTextColor(dc, kText);

    if (control == g_title) {
        SetBkColor(dc, kBg);
        SetTextColor(dc, kAccentEdge);
    } else if (control == g_subtitle || control == g_seedLabel) {
        SetBkColor(dc, kBg);
        SetTextColor(dc, kTextDim);
    } else if (control == g_kernelBadge) {
        SetBkColor(dc, kBg);
        SetTextColor(dc, BadgeColour());
    } else if (control == g_status) {
        SetBkColor(dc, kBg);
        SetTextColor(dc, StatusColour());
    } else if (control == g_log) {
        SetBkColor(dc, kPanel);
        SetTextColor(dc, RGB(214, 206, 230));
        return reinterpret_cast<LRESULT>(g_panelBrush);
    } else if (control == g_seed) {
        SetBkColor(dc, RGB(14, 9, 22));
        SetTextColor(dc, kText);
        static HBRUSH input = CreateSolidBrush(RGB(14, 9, 22));
        return reinterpret_cast<LRESULT>(input);
    }
    UNREFERENCED_PARAMETER(message);
    SetTextColor(dc, kTextDim);
    return reinterpret_cast<LRESULT>(g_bgBrush);
}

LRESULT OnDrawItem(const DRAWITEMSTRUCT* item)
{
    if (item == nullptr || item->CtlType != ODT_BUTTON) {
        return FALSE;
    }
    if (IsPrimary(item->CtlID) || item->CtlID == kIdReapply || item->CtlID == kIdVerify ||
        item->CtlID == kIdStatus || item->CtlID == kIdRestore || item->CtlID == kIdUninstall ||
        item->CtlID == kIdRestart || item->CtlID == kIdElevate) {
        DrawActionButton(item);
        return TRUE;
    }
    if (item->CtlID == kIdSkipDriver || item->CtlID == kIdSkipRegistry ||
        item->CtlID == kIdSkipNetwork || item->CtlID == kIdDryRun) {
        DrawCheckBox(item);
        return TRUE;
    }
    return FALSE;
}

LRESULT CALLBACK WindowProc(HWND window, UINT message, WPARAM wparam, LPARAM lparam)
{
    switch (message) {
    case WM_CREATE:
        g_window = window;
        CreateControls(window);
        return 0;

    case WM_ERASEBKGND:
        return 1;

    case WM_PAINT:
        PaintChrome(window);
        return 0;

    case WM_GETMINMAXINFO: {
        auto* info = reinterpret_cast<MINMAXINFO*>(lparam);
        info->ptMinTrackSize.x = Scale(900);
        info->ptMinTrackSize.y = Scale(660);
        return 0;
    }

    case WM_CTLCOLORSTATIC:
    case WM_CTLCOLOREDIT:
        return OnCtlColour(message, wparam, lparam);

    case WM_DRAWITEM:
        return OnDrawItem(reinterpret_cast<const DRAWITEMSTRUCT*>(lparam));

    case WM_COMMAND: {
        const int id = LOWORD(wparam);
        if (HIWORD(wparam) != BN_CLICKED) {
            break;
        }
        if (IsCheckId(id)) {
            ToggleCheck(id);
            InvalidateRect(reinterpret_cast<HWND>(lparam), nullptr, TRUE);
            if (id == kIdReveal) {
                /* Lines already in the box keep whatever they printed as. Say
                   that out loud, or the tick looks broken. */
                AppendLog(CheckState(kIdReveal)
                              ? L"reveal on: the next job prints real values in clear"
                              : L"reveal off: the next job masks real values again");
            }
            return 0;
        }
        switch (id) {
        case kIdSpoof:
            StartJob(app::Mode::Spoof);
            return 0;
        case kIdInstall:
            StartJob(app::Mode::Install);
            return 0;
        case kIdReapply:
            StartJob(app::Mode::Reapply);
            return 0;
        case kIdVerify:
            StartJob(app::Mode::Verify);
            return 0;
        case kIdStatus:
            StartJob(app::Mode::Status);
            return 0;
        case kIdRestore:
            StartJob(app::Mode::Restore);
            return 0;
        case kIdRestart: {
            if (MessageBoxW(window,
                            L"Restart now? Registry, hostname and volume changes settle on boot.",
                            kWindowTitle, MB_ICONQUESTION | MB_YESNO) != IDYES) {
                return 0;
            }
            std::wstring error;
            if (util::RebootNow(error)) {
                SetStatus(L"Restarting in 5 seconds", kWarn);
            } else {
                MessageBoxW(window, error.c_str(), kWindowTitle, MB_ICONWARNING | MB_OK);
                SetStatus(L"Restart request failed", kErr);
            }
            return 0;
        }
        case kIdUninstall:
            if (MessageBoxW(window, L"Restore every value and remove the driver service?",
                            kWindowTitle, MB_ICONQUESTION | MB_YESNO) == IDYES) {
                StartJob(app::Mode::Uninstall);
            }
            return 0;
        case kIdElevate: {
            if (util::RelaunchElevatedDetached(L"")) {
                DestroyWindow(window);
            } else {
                MessageBoxW(window, L"Elevation was cancelled or refused.", kWindowTitle,
                            MB_ICONWARNING | MB_OK);
                SetStatus(L"Not elevated", kErr);
            }
            return 0;
        }
        default:
            break;
        }
        break;
    }

    case kMsgDone:
        FinishJob(static_cast<int>(wparam));
        return 0;

    case WM_CLOSE:
        if (g_running) {
            MessageBoxW(window, L"A job is still running. Wait for it to finish.", kWindowTitle,
                        MB_ICONINFORMATION | MB_OK);
            return 0;
        }
        DestroyWindow(window);
        return 0;

    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;

    default:
        break;
    }
    return DefWindowProcW(window, message, wparam, lparam);
}

} // namespace

int WINAPI wWinMain(HINSTANCE instance, HINSTANCE previous, PWSTR commandLine, int show)
{
    UNREFERENCED_PARAMETER(previous);
    UNREFERENCED_PARAMETER(show);

    SetProcessDPIAware();
    SetConsoleOutputCP(CP_UTF8);

    INITCOMMONCONTROLSEX controls{sizeof(controls), ICC_STANDARD_CLASSES};
    (VOID)InitCommonControlsEx(&controls);

    /* Any argument means a headless run; the CLI parser owns it. */
    if (commandLine != nullptr && commandLine[0] != L'\0') {
        /*
         * A GUI-subsystem image gets no console of its own, so a headless run
         * would print into nothing. Borrow the caller's console when there is
         * one; when there is not, the log file still gets every line.
         */
        const HANDLE stdOut = GetStdHandle(STD_OUTPUT_HANDLE);
        if (stdOut == nullptr || stdOut == INVALID_HANDLE_VALUE) {
            if (AttachConsole(ATTACH_PARENT_PROCESS)) {
                FILE* console = nullptr;
                (VOID)freopen_s(&console, "CONOUT$", "w", stdout);
                (VOID)freopen_s(&console, "CONOUT$", "w", stderr);
            }
        }

        int argc = 0;
        wchar_t** argv = CommandLineToArgvW(GetCommandLineW(), &argc);
        if (argv == nullptr) {
            return 1;
        }
        app::Options options;
        std::wstring error;
        const bool parsed = app::ParseArgs(argc, argv, options, error);
        LocalFree(argv);

        util::SetLogFile(util::JoinPath(util::ExeDirectory(), L"hwidspoof.log"));
        if (!parsed) {
            util::Logf(util::Level::Error, L"%ls", error.c_str());
            return 1;
        }
        if (options.mode == app::Mode::None) {
            app::PrintUsage();
            return 0;
        }
        if (app::NeedsElevation(options) && !util::IsElevated()) {
            MessageBoxW(nullptr, L"Run this elevated.", kWindowTitle, MB_ICONWARNING | MB_OK);
            return 1;
        }
        return app::Run(options);
    }

    app::ApplyDefaults(g_base);
    util::SetLogFile(util::JoinPath(util::ExeDirectory(), L"hwidspoof.log"));
    util::SetVerbose(true);
    util::SetLogSink([](const std::wstring& line) { AppendLog(line); });

    /*
     * Elevation is not fatal. Try the relaunch once; if the prompt is
     * cancelled, build the window read-only with a restart button instead of
     * vanishing, which is what a failed UAC used to look like.
     */
    g_elevated = util::IsElevated();
    if (!g_elevated) {
        if (!util::RelaunchElevatedDetached(L"")) {
            MessageBoxW(nullptr,
                        L"Administrator rights are required. Right-click hwidspoof.exe and choose "
                        L"Run as administrator.",
                        kWindowTitle, MB_ICONWARNING | MB_OK);
            return 1;
        }
        return 0;
    }

    WNDCLASSEXW windowClass{};
    windowClass.cbSize = sizeof(windowClass);
    windowClass.lpfnWndProc = WindowProc;
    windowClass.hInstance = instance;
    windowClass.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    windowClass.hbrBackground = nullptr;
    windowClass.lpszClassName = kWindowClass;
    const HICON bigIcon = static_cast<HICON>(LoadImageW(
        instance, MAKEINTRESOURCEW(1), IMAGE_ICON, GetSystemMetrics(SM_CXICON),
        GetSystemMetrics(SM_CYICON), LR_DEFAULTCOLOR));
    const HICON smallIcon = static_cast<HICON>(LoadImageW(
        instance, MAKEINTRESOURCEW(1), IMAGE_ICON, GetSystemMetrics(SM_CXSMICON),
        GetSystemMetrics(SM_CYSMICON), LR_DEFAULTCOLOR));
    windowClass.hIcon = bigIcon != nullptr ? bigIcon : MakeAppIcon();
    windowClass.hIconSm = smallIcon != nullptr ? smallIcon : windowClass.hIcon;
    if (RegisterClassExW(&windowClass) == 0) {
        return 1;
    }

    RECT rect{0, 0, Scale(900), Scale(640)};
    AdjustWindowRect(&rect, WS_OVERLAPPEDWINDOW, FALSE);
    const HWND window = CreateWindowExW(
        0, kWindowClass, kWindowTitle,
        (WS_OVERLAPPEDWINDOW & ~WS_THICKFRAME & ~WS_MAXIMIZEBOX) | WS_CLIPCHILDREN,
        CW_USEDEFAULT, CW_USEDEFAULT, rect.right - rect.left, rect.bottom - rect.top, nullptr,
        nullptr, instance, nullptr);
    if (window == nullptr) {
        return 1;
    }

    /*
     * Dark title bar. 20 is DWMWA_USE_IMMERSIVE_DARK_MODE on current builds,
     * 19 on 1809-1909; sending both is harmless because the wrong one fails.
     */
    {
        const BOOL dark = TRUE;
        (VOID)DwmSetWindowAttribute(window, 20, &dark, sizeof(dark));
        (VOID)DwmSetWindowAttribute(window, 19, &dark, sizeof(dark));
    }

    ShowWindow(window, SW_SHOW);
    UpdateWindow(window);

    if (g_elevated) {
        SetStatus(L"Elevated", kOk);
    } else {
        SetStatus(L"Not elevated - actions disabled", kErr);
    }

    MSG message{};
    while (GetMessageW(&message, nullptr, 0, 0) > 0) {
        TranslateMessage(&message);
        DispatchMessageW(&message);
    }
    return static_cast<int>(message.wParam);
}
