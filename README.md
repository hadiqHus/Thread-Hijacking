### Overview
This program performs the following actions:

1. **Process Detection**: It detects if Notepad (`notepad.exe`) is running and retrieves its process ID (PID).
2. **Shellcode Injection**: It injects shellcode into the memory of the target process (Notepad) and hijacks one of its threads to execute the injected shellcode.
3. **Keylogger**: It implements a basic keylogger to capture and log keystrokes.
4. **Process Interaction**: It starts both Notepad and Process Hacker 2 for the user.

### Steps Performed

1. **Keylogger Initialization**:
   - A separate thread is created to run the keylogger, capturing all keystrokes and logging them to a file.

2. **Shellcode Logging**:
   - The shellcode is written into a file for future reference.

3. **Start Notepad**:
   - The program launches Notepad (`C:\\Windows\\System32\\notepad.exe`).

4. **Start Process Hacker 2**:
   - Process Hacker 2 is also launched to allow manual inspection of the processes (optional, for demonstration purposes).

5. **Shellcode Injection and Execution**:
   - The program waits for the user to input the process ID of Notepad. It then injects shellcode into the Notepad process and hijacks a thread to execute the shellcode.

6. **Memory Display**:
   - A message box is shown with the memory address where the shellcode is injected in Notepad.

### Potential Use Cases

- **Learning and Demonstration**: This code is useful for learning about process injection, keylogging, and thread hijacking.
- **Penetration Testing**: It demonstrates a basic method of injecting shellcode and logging keystrokes.
- **Malware Development**: This technique is often used in malicious software, but here it's used for educational purposes.

### Important API Functions

- `CreateToolhelp32Snapshot`: Takes a snapshot of the running processes or threads.
- `Process32First`/`Process32Next`: Iterates through the processes in the snapshot.
- `OpenProcess`: Opens a handle to a process for various operations (e.g., memory manipulation).
- `VirtualAllocEx`: Allocates memory in a remote process.
- `WriteProcessMemory`: Writes data to the memory of a remote process.
- `SetWindowsHookEx`: Installs a hook to intercept low-level keyboard inputs.
- `SuspendThread`/`ResumeThread`: Suspends or resumes execution of a thread.
- `GetThreadContext`/`SetThreadContext`: Retrieves or sets the context (CPU state) of a thread.
- `MessageBoxA`: Displays a message box with custom text.

### Security Implications

- **Keylogging**: This demonstrates a keylogger, which captures and logs keystrokes, potentially used for malicious purposes like password theft.
- **Shellcode Injection**: Injecting shellcode into another process can be a security risk, as it allows execution of arbitrary code in the context of a trusted process (e.g., Notepad).

![image](https://github.com/user-attachments/assets/66afa2d0-4a57-4757-abfa-cc45fb150b79)
![image](https://github.com/user-attachments/assets/4162ab2b-6487-43ba-910c-5712db1c9331)
![image](https://github.com/user-attachments/assets/b12d8b40-5004-4293-b5df-ceb6a50d8e47)
![image](https://github.com/user-attachments/assets/b5049d07-2228-40de-9f2f-b612352bf4bf)
![image](https://github.com/user-attachments/assets/c7e663a1-0f60-416b-93bc-07e8f20201d1)
![image](https://github.com/user-attachments/assets/35f71c77-24fc-41e7-80d6-16c7e8d05aa7)
![image](https://github.com/user-attachments/assets/8b1893a9-ee69-4b47-be01-f078846de239)

