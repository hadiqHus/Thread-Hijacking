# Thread-Hijacking
This code demonstrates a process injection technique, specifically injecting shellcode into a running instance of notepad.exe. 

This code:

Prompts the user to start notepad.exe and Process Hacker 2.
Asks the user for the PID of notepad.exe.
![shellcode](https://github.com/hadiqHus/Thread-Hijacking/assets/64806441/2fc8b834-346e-4f6a-9b53-f32fdea4152d)
Allocates memory in notepad.exe for the shellcode and writes the shellcode to it.
Hijacks a thread in notepad.exe, changes its execution to the shellcode, and resumes it.
Note: This code is for educational purposes only and demonstrates potentially harmful techniques. Running or distributing such code without proper authorization is illegal and unethical. Always use such knowledge responsibly and ethically.
