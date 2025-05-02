#include <windows.h>
#include <string>
#include <vector>
#include <sstream>

// Global variables
HWND g_hwnd;                     // Main window handle
std::vector<std::wstring> g_receivedKeys;  // Store received keystrokes
const int MAX_DISPLAYED_KEYS = 20;         // Maximum number of keys to display
HFONT g_hFont;                   // Font handle

// Forward declarations
LRESULT CALLBACK WndProc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam);
void DrawReceivedKeys(HDC hdc);

// Function to add a message to our display
void AddMessage(const std::wstring& message) {
    g_receivedKeys.push_back(message);
    if (g_receivedKeys.size() > MAX_DISPLAYED_KEYS) {
        g_receivedKeys.erase(g_receivedKeys.begin());
    }
    InvalidateRect(g_hwnd, NULL, TRUE);
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{
    // Register the window class
    const wchar_t CLASS_NAME[] = L"KeyboardEventReceiver";
    
    WNDCLASSW wc = {};
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = CLASS_NAME;
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    
    RegisterClassW(&wc);
    
    // Create the window - using a very visible title
    g_hwnd = CreateWindowExW(
        WS_EX_TOPMOST,              // Make it a topmost window
        CLASS_NAME,                 // Window class
        L"*** KEYBOARD EVENT RECEIVER ***", // Window title - distinct
        WS_OVERLAPPEDWINDOW,        // Window style
        100, 100,                   // Position - more visible than default
        800, 600,                   // Size
        NULL,                       // Parent window    
        NULL,                       // Menu
        hInstance,                  // Instance handle
        NULL                        // Additional application data
    );
    
    if (g_hwnd == NULL)
    {
        MessageBoxW(NULL, L"Failed to create window", L"Error", MB_OK | MB_ICONERROR);
        return 0;
    }
    
    // Create a larger font for better visibility
    g_hFont = CreateFontW(24, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                        ANSI_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                        DEFAULT_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Arial");
    
    // Display the window with maximum visibility
    ShowWindow(g_hwnd, SW_SHOWMAXIMIZED);
    SetForegroundWindow(g_hwnd);
    UpdateWindow(g_hwnd);
    
    // Display our window handle
    std::wstringstream ss;
    ss << L"Window Handle: 0x" << std::hex << (DWORD_PTR)g_hwnd;
    
    // Add initial instructions to the display
    g_receivedKeys.push_back(L"Keyboard Event Receiver");
    g_receivedKeys.push_back(L"---------------------------");
    g_receivedKeys.push_back(ss.str());
    g_receivedKeys.push_back(L"Use me as the target for SoftwareKeyBoard");
    g_receivedKeys.push_back(L"Keep this window in focus/foreground!");
    g_receivedKeys.push_back(L"");
    
    // Flash the window to get attention
    FLASHWINFO fInfo;
    fInfo.cbSize = sizeof(FLASHWINFO);
    fInfo.hwnd = g_hwnd;
    fInfo.dwFlags = FLASHW_ALL | FLASHW_TIMERNOFG;
    fInfo.uCount = 5;
    fInfo.dwTimeout = 0;
    FlashWindowEx(&fInfo);
    
    // Message loop
    MSG msg = {};
    while (GetMessage(&msg, NULL, 0, 0))
    {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    
    // Clean up
    DeleteObject(g_hFont);
    
    return 0;
}

LRESULT CALLBACK WndProc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam)
{
    switch (message)
    {
        case WM_DESTROY:
            PostQuitMessage(0);
            return 0;
            
        case WM_PAINT:
        {
            PAINTSTRUCT ps;
            HDC hdc = BeginPaint(hwnd, &ps);
            
            // Draw the received keys
            DrawReceivedKeys(hdc);
            
            EndPaint(hwnd, &ps);
            return 0;
        }
        
        // Detect when we get or lose focus
        case WM_ACTIVATE:
        {
            if (LOWORD(wParam) == WA_INACTIVE) {
                AddMessage(L"*** Lost focus - SoftwareKeyBoard may not work! ***");
                // Flash to alert user
                FLASHWINFO fInfo;
                fInfo.cbSize = sizeof(FLASHWINFO);
                fInfo.hwnd = hwnd;
                fInfo.dwFlags = FLASHW_ALL;
                fInfo.uCount = 3;
                fInfo.dwTimeout = 0;
                FlashWindowEx(&fInfo);
            } else {
                AddMessage(L"*** Got focus - Ready to receive keys ***");
            }
            return 0;
        }
        
        // Handle individual key presses
        case WM_CHAR:
        {
            wchar_t keyChar = static_cast<wchar_t>(wParam);
            
            // Convert control characters to readable text
            std::wstring keyText;
            if (keyChar == 13) {
                keyText = L"[Enter]";
            } else if (keyChar == 8) {
                keyText = L"[Backspace]";
            } else if (keyChar == 9) {
                keyText = L"[Tab]";
            } else if (keyChar == 27) {
                keyText = L"[Escape]";
            } else if (keyChar == 32) {
                keyText = L"[Space]";
            } else if (keyChar < 32) {
                keyText = L"[Ctrl+" + std::to_wstring(keyChar + 64) + L"]";
            } else {
                keyText = L"Key: ";
                keyText += keyChar;
            }
            
            // Add the key to our vector
            AddMessage(keyText);
            return 0;
        }
        
        // Handle special keys
        case WM_KEYDOWN:
        {
            // Only handle keys that don't generate WM_CHAR messages
            WPARAM vk = wParam;
            if ((vk >= VK_F1 && vk <= VK_F24) ||
                vk == VK_PRINT || vk == VK_SCROLL || vk == VK_PAUSE ||
                vk == VK_INSERT || vk == VK_DELETE ||
                vk == VK_HOME || vk == VK_END ||
                vk == VK_PRIOR || vk == VK_NEXT ||
                vk == VK_LEFT || vk == VK_RIGHT || vk == VK_UP || vk == VK_DOWN) {
                
                std::wstring keyText = L"Special Key: ";
                
                switch (vk) {
                    case VK_F1: keyText += L"F1"; break;
                    case VK_F2: keyText += L"F2"; break;
                    case VK_F3: keyText += L"F3"; break;
                    case VK_F4: keyText += L"F4"; break;
                    case VK_F5: keyText += L"F5"; break;
                    case VK_F6: keyText += L"F6"; break;
                    case VK_F7: keyText += L"F7"; break;
                    case VK_F8: keyText += L"F8"; break;
                    case VK_F9: keyText += L"F9"; break;
                    case VK_F10: keyText += L"F10"; break;
                    case VK_F11: keyText += L"F11"; break;
                    case VK_F12: keyText += L"F12"; break;
                    case VK_PRINT: keyText += L"Print Screen"; break;
                    case VK_SCROLL: keyText += L"Scroll Lock"; break;
                    case VK_PAUSE: keyText += L"Pause"; break;
                    case VK_INSERT: keyText += L"Insert"; break;
                    case VK_DELETE: keyText += L"Delete"; break;
                    case VK_HOME: keyText += L"Home"; break;
                    case VK_END: keyText += L"End"; break;
                    case VK_PRIOR: keyText += L"Page Up"; break;
                    case VK_NEXT: keyText += L"Page Down"; break;
                    case VK_LEFT: keyText += L"Left Arrow"; break;
                    case VK_RIGHT: keyText += L"Right Arrow"; break;
                    case VK_UP: keyText += L"Up Arrow"; break;
                    case VK_DOWN: keyText += L"Down Arrow"; break;
                    default: keyText += L"Unknown"; break;
                }
                
                // Add the key to our vector
                AddMessage(keyText);
            }
            return 0;
        }

        // Ensure we always stay on top
        case WM_KILLFOCUS:
            // Try to recapture focus after a small delay
            SetTimer(hwnd, 1, 100, NULL); 
            return 0;

        case WM_TIMER:
            if (wParam == 1) {
                // Attempt to bring us back to foreground
                SetForegroundWindow(hwnd);
                KillTimer(hwnd, 1);
            }
            return 0;
    }
    
    return DefWindowProc(hwnd, message, wParam, lParam);
}

void DrawReceivedKeys(HDC hdc)
{
    // Set font for better readability
    HFONT hOldFont = (HFONT)SelectObject(hdc, g_hFont);
    
    // Set text color and mode
    SetTextColor(hdc, RGB(0, 0, 0));
    SetBkMode(hdc, TRANSPARENT);
    
    // Draw each received key on a new line
    RECT rect = {20, 20, 780, 50};
    
    for (const auto& keyText : g_receivedKeys)
    {
        DrawTextW(hdc, keyText.c_str(), -1, &rect, DT_LEFT);
        rect.top += 30;     // Increment Y position for next line
        rect.bottom += 30;  // Increment bottom bound accordingly
    }
    
    // Restore previous font
    SelectObject(hdc, hOldFont);
} 
