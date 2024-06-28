# Thread-Hijacking
This code demonstrates a process injection technique, specifically injecting shellcode into a running instance of notepad.exe. 

This code:

# Prompts the user to start notepad.exe and Process Hacker 2.
Asks the user for the PID of notepad.exe (error check).
![module stomp](https://github.com/hadiqHus/Thread-Hijacking/assets/64806441/ab558dff-8662-4846-876a-198b31035c63)
![module stomp 2](https://github.com/hadiqHus/Thread-Hijacking/assets/64806441/6939c5ed-35ff-42a5-abd1-5a899279c480)
# Allocates memory in notepad.exe for the shellcode and writes the shellcode to it.
![processhacker for module stomp](https://github.com/hadiqHus/Thread-Hijacking/assets/64806441/2a49bc89-0eac-4d64-a3b2-7032a983f366)
# Hijacks a thread in notepad.exe, changes its execution to the shellcode, and resumes it.
![shellcode](https://github.com/hadiqHus/Thread-Hijacking/assets/64806441/c6470574-e3be-4a9a-bbcc-638395e41cc5)

Note: This code is for educational purposes only and demonstrates potentially harmful techniques for my cyber awareness project. Running or distributing such code without proper authorization is illegal and unethical. I am not responsible for anything.
