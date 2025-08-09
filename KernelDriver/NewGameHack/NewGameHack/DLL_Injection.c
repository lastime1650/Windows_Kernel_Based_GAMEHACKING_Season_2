#include "DLL_Injection.h"

#include "PE_logic.h"

#include "VirtualMemory.h"

#include "Process.h"

#include "API.h"

NTSTATUS DLL_Inject(

	_In_ HANDLE ProcessId, // Target Process ID

	_In_ PCHAR Injection_Dll_PATH // Hacking Dll Path
) {
	/*
	====================================================

		Kernel Based DLL Injection

		STEP 1) Find the LoadLibraryA API Address in kernel32.dll on Target User Process
		STEP 2) Find Process Handle by Process ID
		STEP 3) DLL Path Copy To Target User Process Memory ( Virtual Allocate and then CopyMemory )
		STEP 4) Start User Mode Thread 

	====================================================
	*/
	NTSTATUS status = STATUS_UNSUCCESSFUL;

	PUCHAR Dll_Base_VirtualAddress = NULL;
	PUCHAR API_VirtualAddress = NULL;

	// STEP 1 
	status = Dll_API_Address_Search(
		ProcessId,
		L"kernel32.dll", // Dll Name
		"LoadLibraryA", // API Name
		&Dll_Base_VirtualAddress, // Dll Base Address
		&API_VirtualAddress // API Address
	);
	if (!NT_SUCCESS(status)) {
		return status;
	}

	// STEP 2 
	HANDLE ProcessHandle;
	status = PID_to_HANDLE(ProcessId, &ProcessHandle);
	if (!NT_SUCCESS(status)) {
		return status; // Failed to get process handle
	}

	// STEP 3
	PUCHAR Dll_Path_VirtualAddress = NULL;
	status = Kernel_Copy_2_Virtual(
		ProcessId, // Target Process id
		(PUCHAR)Injection_Dll_PATH, // Dll Path to Inject
		strlen(Injection_Dll_PATH) + 1, // Dll Path Size ( +1 for null terminator )
		&Dll_Path_VirtualAddress 
	);
	if (!NT_SUCCESS(status)) {
		return status; // Failed to copy DLL path to target process memory
	}


	// STEP 4 
	// Dll Inject START
	status = RtlCreateUserThread(
		ProcessHandle, // Target Process REAL Handle
		NULL, // Security Descriptor
		FALSE, // Create Suspended
		0, // ZeroBits
		0, // Stack Zero
		0, // Stack Zero
		API_VirtualAddress, // LoadLibraryA Address
		Dll_Path_VirtualAddress, // Dll Path to Inject
		NULL, // Thread Handle ( NULL )
		NULL // Client ID ( NULL )

	);


	return status;

}

