#include <iostream>
#include <fstream>
#include <string>
#include <windows.h>
#include <chrono>
#include <ctime>
#include <vector>

// Global file for logging captured keystrokes
std::ofstream logFile;

// Hook handles
HHOOK messageHook;
HHOOK journalHook;
HWND targetWindow = NULL;

// For API hooking
typedef UINT (WINAPI *SendInputType)(UINT, LPINPUT, int);
SendInputType OriginalSendInput = NULL;
SendInputType RealSendInput = NULL;

// Vector to store input events that might be from SendKeys
std::vector<INPUT> currentInputs;

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

// Hooked SendInput function to detect SendKeys calls
UINT WINAPI HookedSendInput(UINT nInputs, LPINPUT pInputs, int cbSize) {
    // Log the SendInput call
    if (logFile.is_open()) {
        logFile << getCurrentTimestamp() << " - " 
                << "SendInput INTERCEPTED - Input count: " << nInputs << std::endl;
        
        // Log each input
        for (UINT i = 0; i < nInputs; i++) {
            if (pInputs[i].type == INPUT_KEYBOARD) {
                WORD vkCode = pInputs[i].ki.wVk;
                DWORD scanCode = pInputs[i].ki.wScan;
                DWORD flags = pInputs[i].ki.dwFlags;
                
                std::string keyName = getKeyName(vkCode);
                std::string eventType = (flags & KEYEVENTF_KEYUP) ? "Key Up" : "Key Down";
                
                logFile << "  - " << eventType << ": " << keyName 
                        << " (VK: " << vkCode << ", Scan: " << scanCode 
                        << ", Flags: 0x" << std::hex << flags << std::dec << ")";
                
                if (flags & KEYEVENTF_EXTENDEDKEY) logFile << " [EXTENDED]";
                if (flags & KEYEVENTF_KEYUP) logFile << " [UP]";
                if (flags & KEYEVENTF_SCANCODE) logFile << " [SCANCODE]";
                if (flags & KEYEVENTF_UNICODE) logFile << " [UNICODE]";
                
                logFile << std::endl;
            }
        }
        
        logFile.flush();
    }
    
    // Save the inputs to our vector in case we want to analyze them later
    currentInputs.clear();
    for (UINT i = 0; i < nInputs; i++) {
        currentInputs.push_back(pInputs[i]);
    }
    
    // Pass through to the real function
    return RealSendInput(nInputs, pInputs, cbSize);
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
        
        // Log all keyboard events, regardless of which window has focus
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
        
        // Get window title of the foreground window
        HWND foregroundWindow = GetForegroundWindow();
        char windowTitle[256] = {0};
        GetWindowTextA(foregroundWindow, windowTitle, sizeof(windowTitle));
        
        // Check if this is a SoftwareKeyBoard window or any window
        bool isSoftwareKeyboard = false;
        if (foregroundWindow == targetWindow || GetParent(foregroundWindow) == targetWindow || 
            strstr(windowTitle, "SoftwareKeyBoard") != NULL) {
            isSoftwareKeyboard = true;
        }
        
        // Extra info about the key event
        std::string flagsInfo = "";
        if (kbdStruct->flags & LLKHF_INJECTED) {
            flagsInfo += " [INJECTED]"; // This is a programmatically generated input
        }
        if (kbdStruct->flags & LLKHF_ALTDOWN) {
            flagsInfo += " [ALT]";
        }
        if (kbdStruct->flags & LLKHF_UP) {
            flagsInfo += " [UP]";
        }
        
        // Log the key event
        if (logFile.is_open()) {
            logFile << getCurrentTimestamp() << " - " 
                    << "Event: " << eventType << " | "
                    << "Key: " << keyName << " | "
                    << "Window: " << windowTitle << " | "
                    << "Is SoftwareKeyboard: " << (isSoftwareKeyboard ? "Yes" : "No") << " | "
                    << "VK Code: " << kbdStruct->vkCode << " | "
                    << "Scan Code: " << kbdStruct->scanCode << " | "
                    << "Flags: " << std::hex << kbdStruct->flags << std::dec 
                    << flagsInfo << std::endl;
            
            // Flush immediately to ensure data is written to file
            logFile.flush();
        }
        
        // Print to console as well
        std::cout << eventType << ": " << keyName << " (Window: " << windowTitle << ")" 
                  << flagsInfo << std::endl;
    }
    
    // Pass to next hook
    return CallNextHookEx(messageHook, nCode, wParam, lParam);
}

// Install API hook for SendInput
bool InstallSendInputHook() {
    // Get the address of the real SendInput function
    HMODULE user32 = GetModuleHandleA("user32.dll");
    if (!user32) {
        return false;
    }
    
    RealSendInput = (SendInputType)GetProcAddress(user32, "SendInput");
    if (!RealSendInput) {
        return false;
    }
    
    // Save the original function address for our hook
    OriginalSendInput = RealSendInput;
    
    // Hook the function by replacing its address in memory
    // This requires modifying memory protection
    DWORD oldProtect;
    if (!VirtualProtect((LPVOID)&RealSendInput, sizeof(UINT_PTR), PAGE_READWRITE, &oldProtect)) {
        return false;
    }
    
    // Replace the pointer
    *(UINT_PTR*)&RealSendInput = (UINT_PTR)HookedSendInput;
    
    // Restore memory protection
    VirtualProtect((LPVOID)&RealSendInput, sizeof(UINT_PTR), oldProtect, &oldProtect);
    
    return true;
}

// Journal record hook - captures SendKeys and other input events
LRESULT CALLBACK JournalRecordProc(int nCode, WPARAM wParam, LPARAM lParam) {
    if (nCode < 0) {
        return CallNextHookEx(journalHook, nCode, wParam, lParam);
    }
    
    if (nCode == HC_ACTION) {
        EVENTMSG* eventMsg = (EVENTMSG*)lParam;
        
        if (eventMsg->message == WM_KEYDOWN || eventMsg->message == WM_KEYUP ||
            eventMsg->message == WM_SYSKEYDOWN || eventMsg->message == WM_SYSKEYUP) {
            
            std::string eventType = (eventMsg->message == WM_KEYDOWN || eventMsg->message == WM_SYSKEYDOWN) 
                                   ? "Journal Key Down" : "Journal Key Up";
            std::string keyName = getKeyName(eventMsg->paramL);
            
            // Log the key event
            if (logFile.is_open()) {
                logFile << getCurrentTimestamp() << " - " 
                        << eventType << ": " << keyName << " | "
                        << "Param: " << eventMsg->paramL << std::endl;
                logFile.flush();
            }
            
            // Print to console as well
            std::cout << eventType << ": " << keyName << std::endl;
        }
    }
    
    return CallNextHookEx(journalHook, nCode, wParam, lParam);
}

int main() {
    std::cout << "Keyboard Event Capture Utility - For SoftwareKeyBoard" << std::endl;
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
    
    // First try: Try to hook the SendInput API (for SendKeys detection)
    if (InstallSendInputHook()) {
        std::cout << "SendInput API hook installed successfully." << std::endl;
        logFile << getCurrentTimestamp() << " - SendInput API hook installed successfully." << std::endl;
    } else {
        std::cout << "Failed to install SendInput API hook. Continuing with other hooks..." << std::endl;
        logFile << getCurrentTimestamp() << " - Failed to install SendInput API hook." << std::endl;
    }
    
    // Second try: Journal record hook (for SendKeys detection)
    journalHook = SetWindowsHookEx(WH_JOURNALRECORD, JournalRecordProc, NULL, 0);
    if (journalHook != NULL) {
        std::cout << "Journal record hook installed successfully." << std::endl;
        logFile << getCurrentTimestamp() << " - Journal record hook installed successfully." << std::endl;
    } else {
        DWORD error = GetLastError();
        std::cout << "Failed to install journal record hook. Error code: " << error << std::endl;
        logFile << getCurrentTimestamp() << " - Failed to install journal record hook. Error code: " 
                << error << std::endl;
    }
    
    // Third try: WH_CALLWNDPROC
    messageHook = SetWindowsHookEx(WH_CALLWNDPROC, MessageProc, NULL, threadId);
    
    if (messageHook == NULL) {
        DWORD error = GetLastError();
        std::cerr << "Failed to install WH_CALLWNDPROC hook. Trying WH_KEYBOARD_LL..." << std::endl;
        logFile << getCurrentTimestamp() << " - Failed to install WH_CALLWNDPROC hook. Error code: " 
                << error << ". Trying WH_KEYBOARD_LL..." << std::endl;
        
        // Fourth try: WH_KEYBOARD_LL (system-wide low-level keyboard hook)
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
    
    std::cout << "Listening for keyboard events from SoftwareKeyBoard..." << std::endl;
    std::cout << "All events will be logged to keyboard_hook_log.txt" << std::endl;
    std::cout << "Press Ctrl+C to exit" << std::endl;
    
    // Message loop to keep application running and processing keyboard events
    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
        
        // Flush log periodically to ensure data is written
        if (logFile.is_open()) {
            logFile.flush();
        }
    }
    
    // Clean up
    if (journalHook != NULL) {
        UnhookWindowsHookEx(journalHook);
    }
    
    if (messageHook != NULL) {
        UnhookWindowsHookEx(messageHook);
    }
    
    logFile << getCurrentTimestamp() << " - Keyboard capture stopped" << std::endl;
    logFile.close();
    
    return 0;
} 
