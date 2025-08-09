#include "MemWrite.h"

#include "Process.h"
#include "VirtualMemory.h"

#include "API.h"

NTSTATUS MemWriting(
	_In_ HANDLE Requester_ProcessId,
	_In_ HANDLE Target_ProecssId,

	_In_ PUCHAR TargetAddress, // ���� ��� �ּ�

	_In_ PUCHAR value_VirtualAddress, // ���� ������ (����)
	_In_ SIZE_T valueSize, // ���� ������ ������

	_In_ BOOLEAN is_Protect_Change_Enable,

	_Out_ PUCHAR* Output // ������ ������ ������ -> VirualAlloc���� �Ҵ�� �޸� �ּ�
) {
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	if (!Output) {
		status = STATUS_INVALID_PARAMETER;
	}

	PProcess_info Requester__processInfo = NULL;
	PProcess_info Target__processInfo = NULL;


	status = GetProcessInfoByProcessId(Requester_ProcessId, &Requester__processInfo);
	if (!NT_SUCCESS(status)) {
		goto EXIT_1;
	}
	
	status = GetProcessInfoByProcessId(Target_ProecssId, &Target__processInfo);
	if (!NT_SUCCESS(status)) {
		goto EXIT_1;
	}

	/*
	
		< CHANGE MEMORY PAGE PROTECT > 
	
	*/
	PUCHAR page_base = NULL;
	SIZE_T page_size = 0;
	BOOLEAN is_change_protect_works = FALSE;// it uses when is_Protect_Change_Enable is true
	ULONG saved_protect = 0; // it uses when is_Protect_Change_Enable is true
	if (is_Protect_Change_Enable) {
		// ��ȣ�Ӽ��� ������ PAGE_EXECUTE_READWRITE�� ����

		// init
		PUCHAR StartAddress = NULL;
		MEMORY_BASIC_INFORMATION memoryInfo = { 0, };


		// search Memory Page
		// * if StartAddress is NULL, it will start from the beginning address
		while (
			NT_SUCCESS(
				ZwQueryVirtualMemory(
					Target__processInfo->ProcessHandle, // Process Handle
					StartAddress, // Start Address
					MemoryBasicInformation, // MEM CLASS
					&memoryInfo, // Memory Basic Information
					sizeof(MEMORY_BASIC_INFORMATION),
					NULL
				)
			)
			) {



			if (
				TargetAddress >= (PUCHAR)memoryInfo.BaseAddress &&
				TargetAddress < ((PUCHAR)memoryInfo.BaseAddress + memoryInfo.RegionSize)
				) {

				page_base = (PUCHAR)memoryInfo.BaseAddress;
				page_size = memoryInfo.RegionSize;

				PUCHAR page_base_tmp = (PUCHAR)memoryInfo.BaseAddress;
				SIZE_T page_regionsize_tmp = memoryInfo.RegionSize;
				status = ZwProtectVirtualMemory(
					Target__processInfo->ProcessHandle,
					&page_base_tmp,
					&page_regionsize_tmp,
					PAGE_EXECUTE_READWRITE,
					&saved_protect
				);
				if (!NT_SUCCESS(status))
					is_change_protect_works = FALSE;
				else
					is_change_protect_works = TRUE;

				break;
			}



			StartAddress = (PUCHAR)memoryInfo.BaseAddress + memoryInfo.RegionSize;
		}
	}
	

	SIZE_T returnByte = 0;
	status = MmCopyVirtualMemory(

		Requester__processInfo->ProcessObject,
		value_VirtualAddress,

		Target__processInfo->ProcessObject,
		TargetAddress,

		valueSize,
		KernelMode,
		&returnByte
	);
	

	if (!NT_SUCCESS(status)) {
		*Output = NULL;
	}
	else {
		*Output = TargetAddress;
	}

	/*
	
		< RECOVER MEMORY PROTECT >

	*/
	if (is_change_protect_works) {
		ULONG previousprotect = 0;
		ZwProtectVirtualMemory(
			Target__processInfo->ProcessHandle,
			&page_base,
			&page_size,
			saved_protect,
			&previousprotect
		);
	}
	

EXIT_1:
	if (Requester__processInfo)
		ReleaseProcessInfo(Requester__processInfo);

	if (Target__processInfo)
		ReleaseProcessInfo(Target__processInfo);

	return status;
}