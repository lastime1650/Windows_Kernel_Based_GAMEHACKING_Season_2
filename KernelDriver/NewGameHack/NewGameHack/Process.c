#pragma warning(disable:4996)
#include "Process.h"

#include "API.h"

// ProcessId to Process_info
NTSTATUS GetProcessInfoByProcessId( //* Increment reference
	_In_ HANDLE ProcessId,
	_Out_ PProcess_info* ProcessInfo
) {
	if (!ProcessInfo)
		return STATUS_INVALID_PARAMETER;

	NTSTATUS status = STATUS_SUCCESS;
	PEPROCESS processObject = NULL;

	// Open the process by ID
	status = PsLookupProcessByProcessId(ProcessId, &processObject);
	if (!NT_SUCCESS(status)) {
		return status; // Failed to get process object
	}

	// allocate
	*ProcessInfo = (PProcess_info)ExAllocatePoolWithTag(
		NonPagedPool,
		sizeof(Process_info),
		'Proc' // Tag for memory allocation
	);
	if (!(*ProcessInfo)) {
		ObDereferenceObject(processObject); // Release the process object if allocation fails
		return STATUS_INSUFFICIENT_RESOURCES; // Memory allocation failed
	}

	/*
		// Initialize ProcessInfo structure
	*/

	// Pid to Handle
	status = PID_to_HANDLE(ProcessId, &(*ProcessInfo)->ProcessHandle);
	if (!NT_SUCCESS(status)) {
		ExFreePoolWithTag(*ProcessInfo, 'Proc'); // Free allocated memory if handle lookup fails
		ObDereferenceObject(processObject); // Release the process object
		return status; // Failed to get process handle
	}
	(*ProcessInfo)->ProcessId = ProcessId;
	(*ProcessInfo)->ProcessObject = processObject;

	// Increment reference count for the process object
	//ObReferenceObject(processObject);

	(*ProcessInfo)->is64bit = ( PsGetProcessWow64Process(processObject) == NULL );

	return status;
}

NTSTATUS ReleaseProcessInfo(		//* Decrement reference
	_In_ PProcess_info ProcessInfo
){
	if (!ProcessInfo)
		return STATUS_INVALID_PARAMETER;

	ObCloseHandle(ProcessInfo->ProcessHandle, KernelMode);

	// decrement reference count 
	ObReferenceObject(ProcessInfo->ProcessObject);

	ExFreePoolWithTag(ProcessInfo, 'Proc');
	return STATUS_SUCCESS;
}


///

NTSTATUS PID_to_HANDLE(
	_In_ HANDLE ProcessId,
	_Out_ HANDLE* ProcessHandle
) {
	if (!ProcessHandle)
		return STATUS_INVALID_PARAMETER;

	NTSTATUS status = STATUS_SUCCESS;

	PEPROCESS eprocess = NULL;
	status = PsLookupProcessByProcessId(ProcessId, &eprocess);
	if (!NT_SUCCESS(status)) {
		return status; // Failed to get process object
	}

	status = ObOpenObjectByPointer(
		eprocess,
		OBJ_KERNEL_HANDLE,
		NULL,
		PROCESS_ALL_ACCESS, // Adjust access rights as needed
		*PsProcessType,
		KernelMode,
		ProcessHandle
	);
	if (!NT_SUCCESS(status)) {
		ObDereferenceObject(eprocess); 
		return status; // Failed to get process object
	}

	return STATUS_SUCCESS;
}