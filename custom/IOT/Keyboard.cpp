#include <iostream>
#include <fstream>
#include <string>
#include <windows.h>
#include <chrono>
#include <ctime>

// Global file for logging captured keystrokes
std::ofstream logFile;

// Hook handle
HHOOK keyboardHook;
HWND targetWindow = NULL;

// Window procedure hook
WNDPROC originalWndProc = NULL;

// For monitoring keyboard state
BYTE keyboardState[256] = {0};
BYTE lastKeyboardState[256] = {0};

// Convert virtual key code to string representation
std::string getKeyName(DWORD vkCode) {
    char keyName[256] = {0};
    DWORD scanCode = MapVirtualKey(vkCode, MAPVK_VK_TO_VSC);
    
    // Handle special keys
    switch (vkCode) {
        case VK_RETURN: return "Enter";
        case VK_ESCAPE: return "Escape";
        case VK_BACK: return "Backspace";
        case VK_TAB: return "Tab";
        case VK_SPACE: return "Space";
        case VK_SHIFT: case VK_LSHIFT: case VK_RSHIFT: return "Shift";
        case VK_CONTROL: case VK_LCONTROL: case VK_RCONTROL: return "Control";
        case VK_MENU: case VK_LMENU: case VK_RMENU: return "Alt";
        default:
            // For standard keys, get the key name from the system
            GetKeyNameTextA(scanCode << 16, keyName, sizeof(keyName));
            if (strlen(keyName) > 0) {
                return keyName;
            }
            // For other keys just return the virtual key code
            return "Key(" + std::to_string(vkCode) + ")";
    }
}

std::string getCurrentTimestamp() {
    auto now = std::chrono::system_clock::now();
    std::time_t time = std::chrono::system_clock::to_time_t(now);
    
    std::string timeStr = std::ctime(&time);
    // Remove newline
    if (!timeStr.empty() && timeStr[timeStr.length() - 1] == '\n') {
        timeStr.erase(timeStr.length() - 1);
    }
    
    return timeStr;
}

// Poll keyboard state changes instead of relying on hooks
void CheckKeyboardChanges() {
    // Get current keyboard state
    GetKeyboardState(keyboardState);
    
    // Check for changes
    for (int i = 0; i < 256; i++) {
        // Check if key state changed
        if ((keyboardState[i] & 0x80) != (lastKeyboardState[i] & 0x80)) {
            if (keyboardState[i] & 0x80) {
                // Key down
                std::string keyName = getKeyName(i);
                
                HWND foregroundWindow = GetForegroundWindow();
                char windowTitle[256] = {0};
                GetWindowTextA(foregroundWindow, windowTitle, sizeof(windowTitle));
                
                // Log the key event
                if (logFile.is_open()) {
                    logFile << getCurrentTimestamp() << " - " 
                            << "Key Down (Polling): " << keyName << " | "
                            << "Window: " << windowTitle << " | "
                            << "VK Code: " << i << std::endl;
                    logFile.flush();
                }
                
                // Print to console as well
                std::cout << "Key Down (Polling): " << keyName << " (Window: " << windowTitle << ")" << std::endl;
            } else {
                // Key up
                std::string keyName = getKeyName(i);
                
                HWND foregroundWindow = GetForegroundWindow();
                char windowTitle[256] = {0};
                GetWindowTextA(foregroundWindow, windowTitle, sizeof(windowTitle));
                
                // Log the key event
                if (logFile.is_open()) {
                    logFile << getCurrentTimestamp() << " - " 
                            << "Key Up (Polling): " << keyName << " | "
                            << "Window: " << windowTitle << " | "
                            << "VK Code: " << i << std::endl;
                    logFile.flush();
                }
                
                // Print to console as well
                std::cout << "Key Up (Polling): " << keyName << " (Window: " << windowTitle << ")" << std::endl;
            }
        }
    }
    
    // Update last keyboard state
    memcpy(lastKeyboardState, keyboardState, sizeof(keyboardState));
}

// Subclass procedure for the target window
LRESULT CALLBACK SubclassWindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    // Check for keyboard messages
    if (uMsg == WM_CHAR || uMsg == WM_KEYDOWN || uMsg == WM_KEYUP || 
        uMsg == WM_SYSKEYDOWN || uMsg == WM_SYSKEYUP) {
        
        std::string messageType;
        switch (uMsg) {
            case WM_CHAR: messageType = "WM_CHAR"; break;
            case WM_KEYDOWN: messageType = "WM_KEYDOWN"; break;
            case WM_KEYUP: messageType = "WM_KEYUP"; break;
            case WM_SYSKEYDOWN: messageType = "WM_SYSKEYDOWN"; break;
            case WM_SYSKEYUP: messageType = "WM_SYSKEYUP"; break;
            default: messageType = "Unknown"; break;
        }
        
        std::string keyInfo;
        if (uMsg == WM_CHAR) {
            char c = (char)wParam;
            keyInfo = isprint(c) ? std::string(1, c) : "ASCII(" + std::to_string((int)c) + ")";
        } else {
            keyInfo = getKeyName((DWORD)wParam);
        }
        
        char windowTitle[256] = {0};
        GetWindowTextA(hwnd, windowTitle, sizeof(windowTitle));
        
        // Log the message
        if (logFile.is_open()) {
            logFile << getCurrentTimestamp() << " - " 
                    << "Subclass: " << messageType << " | "
                    << "Key: " << keyInfo << " | "
                    << "Window: " << windowTitle << " | "
                    << "wParam: " << wParam << " | "
                    << "lParam: " << lParam << std::endl;
            logFile.flush();
        }
        
        std::cout << "Subclass: " << messageType << " - " << keyInfo << " (Window: " << windowTitle << ")" << std::endl;
    }
    
    // Pass to original window procedure
    return CallWindowProcA(originalWndProc, hwnd, uMsg, wParam, lParam);
}

// Callback function for window enumeration to find child edit control
BOOL CALLBACK EnumChildProc(HWND hwnd, LPARAM lParam) {
    char className[256] = {0};
    GetClassNameA(hwnd, className, sizeof(className));
    
    // Look for edit controls - they receive keyboard input
    if (strcmp(className, "EDIT") == 0 || strcmp(className, "JanusGridEdit") == 0 || 
        strcmp(className, "UIEditBox") == 0 || strstr(className, "Edit") != NULL) {
        
        HWND* result = (HWND*)lParam;
        *result = hwnd;
        
        // Found what we were looking for
        std::cout << "Found edit control: " << className << " (HWND: " << hwnd << ")" << std::endl;
        if (logFile.is_open()) {
            logFile << getCurrentTimestamp() << " - Found edit control: " 
                    << className << " (HWND: " << hwnd << ")" << std::endl;
        }
        
        // Subclass the edit control
        originalWndProc = (WNDPROC)SetWindowLongPtrA(hwnd, GWLP_WNDPROC, (LONG_PTR)SubclassWindowProc);
        
        if (originalWndProc == NULL) {
            DWORD error = GetLastError();
            std::cerr << "Failed to subclass window! Error: " << error << std::endl;
            if (logFile.is_open()) {
                logFile << getCurrentTimestamp() << " - Failed to subclass window. Error code: " 
                        << error << std::endl;
            }
        } else {
            std::cout << "Successfully subclassed edit control window." << std::endl;
            if (logFile.is_open()) {
                logFile << getCurrentTimestamp() << " - Successfully subclassed edit control window." << std::endl;
            }
        }
        
        return FALSE;  // Stop enumeration
    }
    
    // Continue enumeration
    return TRUE;
}

// Callback function for window enumeration
BOOL CALLBACK EnumWindowsProc(HWND hwnd, LPARAM lParam) {
    char windowTitle[256];
    GetWindowTextA(hwnd, windowTitle, sizeof(windowTitle));
    
    // Find the SoftwareKeyBoard window
    if (strstr(windowTitle, "SoftwareKeyBoard") != NULL) {
        targetWindow = hwnd;
        std::cout << "Found SoftwareKeyBoard window: " << windowTitle << " (HWND: " << hwnd << ")" << std::endl;
        if (logFile.is_open()) {
            logFile << getCurrentTimestamp() << " - Found SoftwareKeyBoard window: " 
                   << windowTitle << " (HWND: " << hwnd << ")" << std::endl;
        }
        
        // Now find edit controls that might receive keyboard input
        HWND editControl = NULL;
        EnumChildWindows(hwnd, EnumChildProc, (LPARAM)&editControl);
        
        // Stop enumeration as we found our target
        return FALSE;
    }
    
    return TRUE; // Continue enumeration
}

// Callback function for system-wide keyboard hook
LRESULT CALLBACK KeyboardHookProc(int nCode, WPARAM wParam, LPARAM lParam) {
    // If nCode is less than zero, pass to next hook
    if (nCode < 0) {
        return CallNextHookEx(keyboardHook, nCode, wParam, lParam);
    }
    
    // Process keyboard events
    if (nCode == HC_ACTION) {
        KBDLLHOOKSTRUCT* kbdStruct = (KBDLLHOOKSTRUCT*)lParam;
        
        // Log all keyboard events, not just those for our window
        std::string eventType;
        if (wParam == WM_KEYDOWN || wParam == WM_SYSKEYDOWN) {
            eventType = "Key Down";
        } else if (wParam == WM_KEYUP || wParam == WM_SYSKEYUP) {
            eventType = "Key Up";
        } else {
            eventType = "Other";
        }
        
        std::string keyName = getKeyName(kbdStruct->vkCode);
        
        HWND foregroundWindow = GetForegroundWindow();
        char windowTitle[256] = {0};
        GetWindowTextA(foregroundWindow, windowTitle, sizeof(windowTitle));
        
        // Check if this is the SoftwareKeyBoard window
        bool isSoftwareKeyboard = (foregroundWindow == targetWindow || 
                                  GetParent(foregroundWindow) == targetWindow || 
                                  strstr(windowTitle, "SoftwareKeyBoard") != NULL);
        
        // Log the key event
        if (logFile.is_open()) {
            logFile << getCurrentTimestamp() << " - " 
                    << eventType << ": " << keyName << " | "
                    << "Window: " << windowTitle << " | "
                    << "Is SoftwareKeyboard: " << (isSoftwareKeyboard ? "Yes" : "No") << " | "
                    << "VK Code: " << kbdStruct->vkCode << " | "
                    << "Injected: " << ((kbdStruct->flags & LLKHF_INJECTED) ? "Yes" : "No") << std::endl;
            logFile.flush();
        }
        
        // Print to console as well
        std::cout << eventType << ": " << keyName << " (Window: " << windowTitle 
                  << ", Injected: " << ((kbdStruct->flags & LLKHF_INJECTED) ? "Yes" : "No") << ")" << std::endl;
    }
    
    // Pass to next hook
    return CallNextHookEx(keyboardHook, nCode, wParam, lParam);
}

// Thread to poll keyboard state periodically
DWORD WINAPI PollingThread(LPVOID lpParam) {
    while (true) {
        CheckKeyboardChanges();
        Sleep(100); // Poll 10 times per second
    }
    return 0;
}

int main() {
    std::cout << "Keyboard Event Capture for SoftwareKeyBoard" << std::endl;
    std::cout << "==================================================================" << std::endl;
    
    // Open log file
    logFile.open("keyboard_hook_log.txt", std::ios::out | std::ios::app);
    if (!logFile.is_open()) {
        std::cerr << "Failed to open log file!" << std::endl;
        return 1;
    }
    
    logFile << "\n\n" << getCurrentTimestamp() << " - Keyboard capture started" << std::endl;
    
    // Find the SoftwareKeyBoard window
    std::cout << "Looking for SoftwareKeyBoard window..." << std::endl;
    EnumWindows(EnumWindowsProc, 0);
    
    if (targetWindow == NULL) {
        std::cerr << "SoftwareKeyBoard window not found! Make sure it's running." << std::endl;
        logFile << getCurrentTimestamp() << " - SoftwareKeyBoard window not found!" << std::endl;
        logFile.close();
        return 1;
    }
    
    // Start the keyboard polling thread
    HANDLE hPollingThread = CreateThread(NULL, 0, PollingThread, NULL, 0, NULL);
    if (hPollingThread == NULL) {
        std::cerr << "Failed to create polling thread!" << std::endl;
        logFile << getCurrentTimestamp() << " - Failed to create polling thread. Error code: " 
                << GetLastError() << std::endl;
    } else {
        std::cout << "Keyboard polling thread started." << std::endl;
        logFile << getCurrentTimestamp() << " - Keyboard polling thread started." << std::endl;
    }
    
    // Set up the low-level keyboard hook
    keyboardHook = SetWindowsHookEx(WH_KEYBOARD_LL, KeyboardHookProc, NULL, 0);
    
    if (keyboardHook == NULL) {
        DWORD error = GetLastError();
        std::cerr << "Failed to install keyboard hook! Error code: " << error << std::endl;
        logFile << getCurrentTimestamp() << " - Failed to install keyboard hook. Error code: " 
                << error << std::endl;
        
        if (hPollingThread != NULL) {
            // We still have the polling thread running
            std::cout << "Continuing with keyboard polling only." << std::endl;
            logFile << getCurrentTimestamp() << " - Continuing with keyboard polling only." << std::endl;
        } else {
            logFile.close();
            return 1;
        }
    } else {
        std::cout << "Low-level keyboard hook installed successfully." << std::endl;
        logFile << getCurrentTimestamp() << " - Low-level keyboard hook installed successfully." << std::endl;
    }
    
    std::cout << "Listening for keyboard events from all windows..." << std::endl;
    std::cout << "All events will be logged to keyboard_hook_log.txt" << std::endl;
    std::cout << "Press Ctrl+C to exit" << std::endl;
    
    // Initialize keyboard state for polling
    GetKeyboardState(lastKeyboardState);
    
    // Message loop to keep application running and processing keyboard events
    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    
    // Clean up
    if (keyboardHook != NULL) {
        UnhookWindowsHookEx(keyboardHook);
    }
    
    if (hPollingThread != NULL) {
        TerminateThread(hPollingThread, 0);
        CloseHandle(hPollingThread);
    }
    
    // Restore original window procedure if we subclassed
    if (originalWndProc != NULL) {
        HWND editControl = NULL;
        EnumChildWindows(targetWindow, EnumChildProc, (LPARAM)&editControl);
        if (editControl != NULL) {
            SetWindowLongPtrA(editControl, GWLP_WNDPROC, (LONG_PTR)originalWndProc);
        }
    }
    
    logFile << getCurrentTimestamp() << " - Keyboard capture stopped" << std::endl;
    logFile.close();
    
    return 0;
} 
