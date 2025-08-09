#ifndef PROCESS_UTIL_H
#define PROCESS_UTIL_H

#include <ntifs.h>

typedef struct Process_info {
	HANDLE ProcessId;
	HANDLE ProcessHandle;
	PEPROCESS ProcessObject; // Reference to the process object
	BOOLEAN is64bit; // if True 64bit , if Flase 32bit
}Process_info, *PProcess_info;


// ProcessId to Process_info
NTSTATUS GetProcessInfoByProcessId( //* Increment reference
	_In_ HANDLE ProcessId,
	_Out_ PProcess_info* ProcessInfo
);

NTSTATUS ReleaseProcessInfo(		//* Decrement reference
	_In_ PProcess_info ProcessInfo
);



NTSTATUS PID_to_HANDLE(
	_In_ HANDLE ProcessId,
	_Out_ HANDLE* ProcessHandle
);

#endif