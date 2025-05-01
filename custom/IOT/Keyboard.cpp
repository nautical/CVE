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

// Convert virtual key code to string representation
std::string getKeyName(DWORD vkCode) {
    char keyName[256] = {0};
    DWORD scanCode = MapVirtualKey(vkCode, MAPVK_VK_TO_VSC);
    
    // Handle special keys
    switch (vkCode) {
        case VK_RETURN:
            return "Enter";
        case VK_ESCAPE:
            return "Escape";
        case VK_BACK:
            return "Backspace";
        case VK_TAB:
            return "Tab";
        case VK_SPACE:
            return "Space";
        case VK_SHIFT:
        case VK_LSHIFT:
        case VK_RSHIFT:
            return "Shift";
        case VK_CONTROL:
        case VK_LCONTROL:
        case VK_RCONTROL:
            return "Control";
        case VK_MENU:
        case VK_LMENU:
        case VK_RMENU:
            return "Alt";
        // Add more special keys as needed
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

// Callback function that processes keyboard events
LRESULT CALLBACK KeyboardProc(int nCode, WPARAM wParam, LPARAM lParam) {
    // If nCode is less than zero, pass to next hook
    if (nCode < 0) {
        return CallNextHookEx(keyboardHook, nCode, wParam, lParam);
    }
    
    // Process keyboard events
    if (nCode == HC_ACTION) {
        KBDLLHOOKSTRUCT* kbdStruct = (KBDLLHOOKSTRUCT*)lParam;
        
        std::string eventType;
        if (wParam == WM_KEYDOWN || wParam == WM_SYSKEYDOWN) {
            eventType = "Key Down";
        } else if (wParam == WM_KEYUP || wParam == WM_SYSKEYUP) {
            eventType = "Key Up";
        } else {
            eventType = "Other";
        }
        
        // Get name of the key
        std::string keyName = getKeyName(kbdStruct->vkCode);
        
        // Get additional information about the key press
        HWND foregroundWindow = GetForegroundWindow();
        char windowTitle[256] = {0};
        GetWindowTextA(foregroundWindow, windowTitle, sizeof(windowTitle));
        
        // Log the key event
        if (logFile.is_open()) {
            logFile << getCurrentTimestamp() << " - " 
                    << "Event: " << eventType << " | "
                    << "Key: " << keyName << " | "
                    << "Window: " << windowTitle << " | "
                    << "VK Code: " << kbdStruct->vkCode << " | "
                    << "Scan Code: " << kbdStruct->scanCode << std::endl;
        }
        
        // Print to console as well
        std::cout << eventType << ": " << keyName << " (Window: " << windowTitle << ")" << std::endl;
    }
    
    // Pass to next hook
    return CallNextHookEx(keyboardHook, nCode, wParam, lParam);
}

int main() {
    std::cout << "Keyboard Hook Demonstration - Captures events from SoftwareKeyBoard" << std::endl;
    std::cout << "==================================================================" << std::endl;
    
    // Open log file
    logFile.open("keyboard_hook_log.txt", std::ios::out | std::ios::app);
    if (!logFile.is_open()) {
        std::cerr << "Failed to open log file!" << std::endl;
        return 1;
    }
    
    logFile << "\n\n" << getCurrentTimestamp() << " - Keyboard hook started" << std::endl;
    
    // Set up keyboard hook
    keyboardHook = SetWindowsHookEx(WH_KEYBOARD_LL, KeyboardProc, NULL, 0);
    
    if (keyboardHook == NULL) {
        std::cerr << "Failed to install keyboard hook!" << std::endl;
        logFile << getCurrentTimestamp() << " - Failed to install keyboard hook. Error code: " 
                << GetLastError() << std::endl;
        logFile.close();
        return 1;
    }
    
    std::cout << "Keyboard hook installed successfully." << std::endl;
    std::cout << "Listening for keyboard events..." << std::endl;
    std::cout << "Press Ctrl+C to exit" << std::endl;
    
    // Message loop to keep application running and processing keyboard events
    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    
    // Clean up
    UnhookWindowsHookEx(keyboardHook);
    logFile << getCurrentTimestamp() << " - Keyboard hook stopped" << std::endl;
    logFile.close();
    
    return 0;
} 
