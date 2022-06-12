# TamperAV
A Demo to tamper 360 Total Security's self protection by patching ObRegisterCallbacks and injecting dll into antivirus process. Then use Rootkit to be more sneaky.

## Features
* Patch Register Callback
    * Thread
    * Process
* Rootkit
    * Hook NtCreateFile to deny file access
    * Hook NtQueryDirectoryFile to hide file
* DLL Injection
    * from user mode

## Usage
1. Load the TamperAVDrv
2. Put the dll (named TamperAV.dll) to `C:\`
3. Execute TamperAV.exe


## Reference
* [FiYHer/InfinityHookPro](https://github.com/FiYHer/InfinityHookPro)
* [XShar/simple_rootkit_for_windows_fork_r77](https://github.com/XShar/simple_rootkit_for_windows_fork_r77)
