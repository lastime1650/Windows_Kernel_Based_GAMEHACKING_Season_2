#include "GetProcessAPIAddress.h"

#include "API.h"

NTSTATUS Call_2_User_Thread(HANDLE ProcessHandle, PVOID UserThreadAddress, PVOID Parameter, HANDLE* return_HANDLE) {

	return RtlCreateUserThread(
		ProcessHandle,
		NULL,
		FALSE,
		0,
		0,
		0,
		UserThreadAddress,
		Parameter,
		return_HANDLE,
		NULL
	);

}

NTSTATUS Get_ALL_APIS(HANDLE ProcessId, Got_UserThread_APIs* output) {

	if (!output)
		return STATUS_INVALID_PARAMETER;

	output->SuspendThread_Address = NULL;
	output->ResumeThread_Address = NULL;
	
	PUCHAR tmp_dll_base_returned = NULL;

	NTSTATUS status = Get_SuspendThread_Address(ProcessId, &tmp_dll_base_returned,  (PUCHAR*) & output->SuspendThread_Address);
	status = Get_ResumeThread_Address(ProcessId, &tmp_dll_base_returned, (PUCHAR*)&output->ResumeThread_Address);


	return status;
}

NTSTATUS Get_SuspendThread_Address(HANDLE Processid, PUCHAR* Dll_Base_VirtualAddress, PUCHAR* API_Base_VirtualAddress) {

	return Dll_API_Address_Search(
		Processid,
		L"kernel32.dll",
		"SuspendThread",
		Dll_Base_VirtualAddress,
		API_Base_VirtualAddress
	);

}
NTSTATUS Get_ResumeThread_Address(HANDLE Processid, PUCHAR* Dll_Base_VirtualAddress, PUCHAR* API_Base_VirtualAddress) {
	return Dll_API_Address_Search(
		Processid,
		L"kernel32.dll",
		"ResumeThread",
		Dll_Base_VirtualAddress,
		API_Base_VirtualAddress
	);
}

