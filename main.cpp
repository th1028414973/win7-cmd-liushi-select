//by tang huai  and gm aige 2025.12.29
#include <windows.h>
#include <string>
// 导出这个函数，方便 Stud_PE 识别
extern "C" __declspec(dllexport) void Init() {}

typedef BOOL(WINAPI* PfnPatBlt)(HDC hdc, int x, int y, int w, int h, DWORD rop);
PfnPatBlt g_OrgPatBlt = PatBlt;
typedef HANDLE(WINAPI *PSET_CLIPBOARD_DATA)(UINT, HANDLE);
PSET_CLIPBOARD_DATA pOriginalSetClipboardData = SetClipboardData;



static short cmdWidth = -1;
static int g_FontW, g_FontH;
// 全局变量，记录选区的锚点
static int g_StartX = -1, g_StartY = -1, Prevmsg;
static int g_CurX = -1, g_CurY = -1, g_PrevCurY, g_PrevCurX;
static bool g_IsSelecting = true;
WNDPROC g_OrgWindowProc = NULL;



const BYTE SIGNATURE[] = { 0x0F, 0xB7, 0x05, 0x00, 0x00, 0x00, 0x00, 0x0F, 0xB7, 0x0D };
const char* SIGN_MASK = "xxx????xxx";

//WORD* g_ptop = NULL;
//WORD* g_pbom = NULL;
WORD* g_pLeft = NULL;
WORD* g_pRight = NULL;

// --- 特征码搜索函数 ---
DWORD_PTR FindSignature(DWORD_PTR base, DWORD size) {
    for (DWORD_PTR i = 0; i < size - sizeof(SIGNATURE); i++) {
        bool found = true;
        for (DWORD_PTR j = 0; j < sizeof(SIGNATURE); j++) {
            if (SIGN_MASK[j] != '?' && SIGNATURE[j] != *(BYTE*)(base + i + j)) {
                found = false;
                break;
            }
        }
        if (found) return base + i;
    }
    return 0;
}


// 计算字符串在控制台显示的实际列数
int GetConsoleDisplayWidth(const std::wstring& str, int *col = nullptr) {
    int width = 0,w=0;
    for (wchar_t c : str) {
        w++;
        if (c > 255) {
            width ++; // 中文占2列
            if (col != nullptr && w <= *col)(*col)--;

        }
        
    }
    return width+w;
}


std::wstring FixClipboardStreaming(std::wstring raw, size_t startcol, int endcol) {
    size_t realColumns = cmdWidth;

    if (raw.empty() || realColumns <= 0) return raw;

    std::wstring result = L"";
    size_t start = startcol;

    while (start < raw.length()) {
        size_t nextNL = raw.find(L"\r\n", start);
        if (nextNL != std::wstring::npos) {
            std::wstring line = raw.substr(start, nextNL - start);
            size_t w = GetConsoleDisplayWidth(line);
            
            if (w + 1 >= (size_t)realColumns - startcol) {
                if (line.back() <= 255 && w == (size_t)realColumns - startcol - 1){
                    line += L" ";
                }
                startcol = 0;
                result += line;
            }
            else {
                result += line + L"\r\n";
            }

            start = nextNL + 2;
        }
        else {

            std::wstring lastLine = raw.substr(start, endcol);
            result += lastLine;
            break;
        }
    }
    return result;
}

LRESULT CALLBACK MyWindowProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    
    switch (msg) {
    case WM_ERASEBKGND:
        return 1;
    case WM_MOUSEACTIVATE:
        if (Prevmsg == WM_NCHITTEST) //WM_NCMOUSEMOVE
        {
            g_IsSelecting = false;
            return MA_ACTIVATEANDEAT; 
            
        }
        
        break;
    case WM_LBUTTONDOWN:
        Prevmsg = false;
        g_StartX = g_CurX = (short)LOWORD(lParam);
        g_StartY = g_CurY = (short)HIWORD(lParam);
        g_PrevCurY = g_CurY;
        g_PrevCurX = g_CurX;
        InvalidateRect(hWnd, NULL, TRUE);
        break;
    case WM_MOUSEMOVE :
        if (wParam & MK_LBUTTON) {
            if (g_IsSelecting) {
                g_CurX = (short)LOWORD(lParam);
                g_CurY = (short)HIWORD(lParam);
                int oldRow = g_PrevCurY / g_FontH;
                int newRow = g_CurY / g_FontH;

                if (oldRow != newRow || abs(g_CurX - g_PrevCurX) > 5) {
                    LockWindowUpdate(hWnd);
                    RECT dirty;
                    GetClientRect(hWnd, &dirty);
                    // 只刷新受影响的行范围
                    dirty.top = min(oldRow, newRow) * g_FontH;
                    dirty.bottom = (max(oldRow, newRow) + 1) * g_FontH;

                    InvalidateRect(hWnd, &dirty, FALSE);
                    g_PrevCurX = g_CurX;
                    g_PrevCurY = g_CurY;
                    LockWindowUpdate(NULL);
                }
            }
            else{
                g_IsSelecting = true;
            }
        } 
        break;
    case WM_GETTEXT:
        if (!g_IsSelecting) {
            InvalidateRect(hWnd, NULL, TRUE);
            g_IsSelecting = true;
        }
    }
    Prevmsg = msg;
    return CallWindowProc(g_OrgWindowProc, hWnd, msg, wParam, lParam);
}

void** FindIatEntry(const char* moduleName, const char* functionName) {

    HMODULE hBase = GetModuleHandleA(NULL);
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hBase;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) return nullptr;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hBase + dosHeader->e_lfanew);
    IMAGE_DATA_DIRECTORY importDirectory = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    PIMAGE_IMPORT_DESCRIPTOR importDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE*)hBase + importDirectory.VirtualAddress);
    while (importDescriptor->Name) {
        const char* currentModuleName = (const char*)((BYTE*)hBase + importDescriptor->Name);

        if (_stricmp(currentModuleName, moduleName) == 0) {
            PIMAGE_THUNK_DATA nameTable = (PIMAGE_THUNK_DATA)((BYTE*)hBase + importDescriptor->OriginalFirstThunk);
            PIMAGE_THUNK_DATA addressTable = (PIMAGE_THUNK_DATA)((BYTE*)hBase + importDescriptor->FirstThunk);
            while (nameTable->u1.AddressOfData) {
                if (!(nameTable->u1.Ordinal & IMAGE_ORDINAL_FLAG)) {
                    PIMAGE_IMPORT_BY_NAME importByName = (PIMAGE_IMPORT_BY_NAME)((BYTE*)hBase + nameTable->u1.AddressOfData);
                    if (strcmp(importByName->Name, functionName) == 0) {
                        return (void**)&addressTable->u1.Function;
                    }
                }
                nameTable++;
                addressTable++;
            }
        }
        importDescriptor++;
    }
    return nullptr;
}


HANDLE WINAPI MySetClipboardData(UINT uFormat, HANDLE hMem) {

    if ((uFormat == CF_TEXT || uFormat == CF_UNICODETEXT) && hMem != NULL) {

        // 1. 锁定内存获取系统原本要存入的字符串
        LPVOID pSrc = GlobalLock(hMem);
        if (pSrc) {
            std::wstring originalText;
            if (uFormat == CF_UNICODETEXT) {
                originalText = (wchar_t*)pSrc;
            }
            else {
                // 如果是窄字符，简单转换一下
                std::string s((char*)pSrc);
                originalText = std::wstring(s.begin(), s.end());
            }
            if (originalText.length()>0)
            {
                int startRow = g_StartY / g_FontH;
                int currentRow = g_CurY / g_FontH;

                int startcol = g_StartX / g_FontW;
                g_CurX = max(g_CurX, 0);
                int endcol = g_CurX / g_FontW;
                if (currentRow != startRow){
                    if (currentRow < startRow) { // 向上选：从行首到起点
                        
                        int tmp = startcol;
                        startcol = endcol;
                        endcol = tmp;

                    }


                    GetConsoleDisplayWidth(originalText.substr(0, originalText.find(L"\r\n")), &startcol);
                    GetConsoleDisplayWidth(originalText.substr(originalText.rfind(L"\r\n") + 2), &endcol);
                    
                    originalText = FixClipboardStreaming(originalText, startcol, endcol<1 ? endcol : ++endcol);
                }
                else{
                    if (startcol > endcol) {
                        
                        int tmp = startcol;
                        startcol = endcol;
                        endcol = tmp;
                    }
                    
                    GetConsoleDisplayWidth(originalText, &startcol);
                    GetConsoleDisplayWidth(originalText, &endcol);
                    if (startcol > originalText.length())
                        originalText = L"";
                    else
                        originalText = originalText.substr(startcol, ++endcol - startcol);
                    
                }
            }
            
            // 重新分配内存并写入
            size_t newSize = (originalText.length() + 1) * sizeof(wchar_t);
            HANDLE hNewMem = GlobalAlloc(GMEM_MOVEABLE, newSize);
            if (hNewMem) {
                memcpy(GlobalLock(hNewMem), originalText.c_str(), newSize);
                GlobalUnlock(hNewMem);

                // 释放原来的 hMem 以防内存泄漏（或者直接返回新句柄让系统处理）
                return pOriginalSetClipboardData(uFormat, hNewMem);
            }

        }
    }
    return pOriginalSetClipboardData(uFormat, hMem);
}


BOOL WINAPI MyPatBlt(HDC hdc, int x, int y, int w, int h, DWORD rop) {

    if (g_OrgWindowProc == NULL) {
        HWND hWnd = WindowFromDC(hdc);
        if (hWnd) {
            g_OrgWindowProc = (WNDPROC)SetWindowLongPtr(hWnd, GWLP_WNDPROC, (LONG_PTR)MyWindowProc); 
            RECT rc;
            GetClientRect(hWnd, &rc);
            int pixelWidth = rc.right; 
            g_IsSelecting = true;
            TEXTMETRIC tm;
            if (GetTextMetrics(hdc, &tm)) {
                g_FontH = (short)(tm.tmHeight + tm.tmExternalLeading);
                g_FontW = (short)tm.tmAveCharWidth; 
            }
            cmdWidth = (short)(pixelWidth / g_FontW);
        }
    }
    if (rop == DSTINVERT) {
        if (h == g_FontH && g_IsSelecting) {
            if (g_StartY == -1)
            {
                g_StartY = g_CurY = y;
                g_StartX = g_CurX = x;
            }
            int winWidth = cmdWidth*g_FontW;
            // --- 核心：转换成逻辑行号 ---
            int startRow = g_StartY / g_FontH;
            int currentRow = g_CurY / g_FontH;
            int thisRow = y / g_FontH; 

            *g_pLeft = 0;
            *g_pRight = cmdWidth - 1;

            if (thisRow > min(startRow, currentRow) && thisRow < max(startRow, currentRow)) {
                return g_OrgPatBlt(hdc, 0, y, winWidth, h, rop);
            }

            if (thisRow == startRow) {
                int startX = (g_StartX / g_FontW) * g_FontW;
                if (currentRow > startRow) { // 向下选：从起点到行末
                    return g_OrgPatBlt(hdc, startX, y, winWidth - startX, h, rop);
                }
                else if (currentRow < startRow) { // 向上选：从行首到起点
                    return g_OrgPatBlt(hdc, 0, y, startX + g_FontW, h, rop);
                }
                else {
                    // 同一行内的处理：系统原生的 w 通常是对的，或者手动算
                    int curX = (g_CurX / g_FontW) * g_FontW;
                    int leftX = min(startX, curX);
                    int rightX = max(startX, curX) + g_FontW;
                    return g_OrgPatBlt(hdc, leftX, y, rightX - leftX, h, rop);
                }
            }
            if (thisRow == currentRow) {
                int curX = (g_CurX / g_FontW) * g_FontW;
                if (currentRow > startRow) {
                    return g_OrgPatBlt(hdc, 0, y, curX + g_FontW, h, rop);
                }
                else if (currentRow < startRow) { 
                    return g_OrgPatBlt(hdc, curX, y, winWidth - curX, h, rop);
                }
            }
        }
        return TRUE; 
    }

    return g_OrgPatBlt(hdc, x, y, w, h, rop);
}



// 3. 执行 Hook 的核心逻辑
void SetIatHook() {
    void** pIatEntry = FindIatEntry("GDI32.dll", "PatBlt");
    DWORD oldProtect;
    if (VirtualProtect(pIatEntry, sizeof(void*), PAGE_EXECUTE_READWRITE, &oldProtect)) {
        *pIatEntry = (void*)&MyPatBlt;
        VirtualProtect(pIatEntry, sizeof(void*), oldProtect, &oldProtect);
    }

    pIatEntry = FindIatEntry("user32.dll", "SetClipboardData");
    if (VirtualProtect(pIatEntry, sizeof(void*), PAGE_EXECUTE_READWRITE, &oldProtect)) {
        *pIatEntry = (void*)&MySetClipboardData;
        VirtualProtect(pIatEntry, sizeof(void*), oldProtect, &oldProtect);
    }
    DWORD_PTR hModule = (DWORD_PTR)GetModuleHandle(NULL);
    DWORD_PTR match = FindSignature(hModule, 0x150000);
    if (match) {

        long relOffset = *(long*)(match + 3);
        g_pLeft = (WORD*)(match + 7 + relOffset);
        //g_ptop = (WORD*)((DWORD_PTR)g_pLeft + 2);

        g_pRight = (WORD*)((DWORD_PTR)g_pLeft + 4);
        //g_pbom = (WORD*)((DWORD_PTR)g_pRight + 2);

    }
    else {
        // 回退方案：硬编码偏移 (版本 6.1.7601.24388)
        g_pLeft = (WORD*)(hModule + 0x263BC);
        //g_ptop = (WORD*)(hModule + 0x263BE);
        g_pRight = (WORD*)(hModule + 0x263C0);
        //g_pbom = (WORD*)(hModule + 0x263C2);
        

    }
    char buf[256];
    sprintf_s(buf, "successful \n");
}




BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);
        SetIatHook();
    }
    return TRUE;
}