#include "DllInject.h"

BOOL ObtainSeDebugPrivilege()
{
				HANDLE hToken;
				PTOKEN_PRIVILEGES NewPrivileges;
				BYTE OldPriv[1024];
				PBYTE pbOldPriv;
				ULONG cbNeeded;
				BOOLEAN fRc;
				LUID LuidPrivilege;

				// Make sure we have access to adjust and to get the old token privileges
				if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
				{
								std::cout << "OpenProcessToken failed with " << GetLastError() << std::endl;

								return FALSE;
				}

				cbNeeded = 0;

				// Initialize the privilege adjustment structure
				LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &LuidPrivilege);

				NewPrivileges = (PTOKEN_PRIVILEGES)LocalAlloc(
								LMEM_ZEROINIT,
								sizeof(TOKEN_PRIVILEGES) + (1 - ANYSIZE_ARRAY) * sizeof(LUID_AND_ATTRIBUTES)
				);
				if (NewPrivileges == NULL) {
								return FALSE;
				}

				NewPrivileges->PrivilegeCount = 1;
				NewPrivileges->Privileges[0].Luid = LuidPrivilege;
				NewPrivileges->Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

				// Enable the privilege
				pbOldPriv = OldPriv;
				fRc = AdjustTokenPrivileges(
								hToken,
								FALSE,
								NewPrivileges,
								1024,
								(PTOKEN_PRIVILEGES)pbOldPriv,
								&cbNeeded
				);

				if (!fRc) {

								// If the stack was too small to hold the privileges
								// then allocate off the heap
								if (GetLastError() == ERROR_INSUFFICIENT_BUFFER) {

												pbOldPriv = (PBYTE)LocalAlloc(LMEM_FIXED, cbNeeded);
												if (pbOldPriv == NULL) {
																return FALSE;
												}

												fRc = AdjustTokenPrivileges(
																hToken,
																FALSE,
																NewPrivileges,
																cbNeeded,
																(PTOKEN_PRIVILEGES)pbOldPriv,
																&cbNeeded
												);
								}
				}
				return fRc;
}

std::uint32_t get_proc_id(const std::wstring& name)
{
				auto result = 0ul;
				auto snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

				if (snapshot == INVALID_HANDLE_VALUE)
								return result;

				// use the wide version of the struct
				auto pe32w = PROCESSENTRY32W{};
				pe32w.dwSize = sizeof(PROCESSENTRY32W);

				if (!Process32FirstW(snapshot, &pe32w))
								return CloseHandle(snapshot), result;

				while (Process32NextW(snapshot, &pe32w))
				{
								// use std::wstring's operator, not comparing pointers here
								if (name == pe32w.szExeFile)
								{
												result = pe32w.th32ProcessID;
												break;
								}
				}

				CloseHandle(snapshot);
				return result;
}

BOOL dllInject() {
				DWORD processid = get_proc_id(L"QHActiveDefense.exe");

				if (processid == 0) {
								std::cout << "pid not found\n";
								return FALSE;
				}
				else {
								std::cout << "pid: " << processid << std::endl;
				}

				ObtainSeDebugPrivilege();

				HANDLE hprocess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processid);
				if (hprocess == NULL) {
								printf("cannot open process: %d\n", GetLastError());
								return FALSE;
				}

				char dllname[150] = "C:\\InjectedDLL_x86.dll";
				int size = strlen(dllname) + 5;
				PVOID procdlladdr = VirtualAllocEx(hprocess, NULL, size, MEM_COMMIT, PAGE_READWRITE);
				if (procdlladdr == NULL) {
								printf("handle %p VirtualAllocEx failed: %d\n", hprocess, GetLastError());
								return 0;
				}
				SIZE_T writenum;

				if (!WriteProcessMemory(hprocess, procdlladdr, dllname, size, &writenum)) {
								printf("handle %p WriteProcessMemory failed\n", hprocess);
								return 0;
				}
				FARPROC loadfuncaddr = GetProcAddress(GetModuleHandle(L"kernel32.dll"), "LoadLibraryA");
				if (!loadfuncaddr) {
								printf("handle %p GetProcAddress failed\n", hprocess);
								return 0;
				}
				HANDLE hthread = CreateRemoteThread(hprocess, NULL, 0, (LPTHREAD_START_ROUTINE)loadfuncaddr, (LPVOID)procdlladdr, 0, NULL);
				if (!hthread) {
								printf("handle %p CreateRemoteThread failed\n", hprocess);
								return 0;
				}

				printf("handle %p Injection done, WaitForSingleObject return %d\n", hprocess, WaitForSingleObject(hthread, INFINITE));
				CloseHandle(hthread);
				CloseHandle(hprocess);
				return TRUE;
}