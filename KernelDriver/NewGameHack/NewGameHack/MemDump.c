#include "MemDump.h"

#include "Process.h"
#include "VirtualMemory.h"

#include "API.h"

#include "Scan.h" 

NTSTATUS MemDumping(
	_In_ HANDLE Requester_ProcessId,
	_In_ HANDLE Target_ProecssId,

	_In_ PUCHAR Start_Dump_Target_Address, // 시작 주소 ( 덤프 타겟 주소 ) 
	_In_ SIZE_T Size, // 덤프할 크기

	_Out_ PMemDumpOutput* DumpedData // 덤프된 데이터 포인터 -> VirualAlloc으로 할당된 메모리 주소
)
{
	PProcess_info Requester__processInfo = NULL;
	PProcess_info Target__processInfo = NULL;


	NTSTATUS status = GetProcessInfoByProcessId(Requester_ProcessId, &Requester__processInfo);
	if (!NT_SUCCESS(status)) {
		goto EXIT_1;
	}
	
	status = GetProcessInfoByProcessId(Target_ProecssId, &Target__processInfo);
	if (!NT_SUCCESS(status)) {
		goto EXIT_1;
	}
	MemDumpOutput output = { 0, };




	PUCHAR page_base = NULL;
	SIZE_T page_size = 0;
	BOOLEAN is_change_protect_works = FALSE;// it uses when is_Protect_Change_Enable is true
	ULONG saved_protect = 0; // it uses when is_Protect_Change_Enable is true
	/*
	
		GET PAGE informations
	
	*/
	// init
	PUCHAR StartAddress = NULL;
	MEMORY_BASIC_INFORMATION memoryInfo = { 0, };

	PUCHAR Dumped_PAGE_BaseAddress = NULL;
	SIZE_T Dumped_PAGE_SIZE = 0;

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
			Start_Dump_Target_Address >= (PUCHAR)memoryInfo.BaseAddress &&
			Start_Dump_Target_Address < ((PUCHAR)memoryInfo.BaseAddress + memoryInfo.RegionSize)
			) {



			// Allocate Page Memory Dump Area of Requester
			

			Dumped_PAGE_SIZE = (SIZE_T)memoryInfo.RegionSize;
			VirtualAllocate(
				Requester__processInfo->ProcessHandle,
				Dumped_PAGE_SIZE,
				&Dumped_PAGE_BaseAddress
			);

			if (!Dumped_PAGE_BaseAddress) {
				status = STATUS_MEMORY_NOT_ALLOCATED;
				goto EXIT_1;
			}


			output.Dumped_PAGE_BasedAddress = Dumped_PAGE_BaseAddress;
			output.PAGE_BaseAddress = (PUCHAR)memoryInfo.BaseAddress;
			output.PAGE_Size = (SIZE_T)memoryInfo.RegionSize;
			output.PAGE_Protect = memoryInfo.Protect;
			output.PAGE_State = memoryInfo.State;



			/*
			
				보호속성 강제 바꾸기
			
			*/
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


			// Target -> Requester Copy
			SIZE_T returnBytes = 0;
			status = MmCopyVirtualMemory(
				Target__processInfo->ProcessObject,
				(PUCHAR)memoryInfo.BaseAddress,

				Requester__processInfo->ProcessObject,
				Dumped_PAGE_BaseAddress,
				(SIZE_T)memoryInfo.RegionSize,
				KernelMode,
				&returnBytes
			);
			if (!NT_SUCCESS(status))
				break;

			



			break;
		}



		StartAddress = (PUCHAR)memoryInfo.BaseAddress + memoryInfo.RegionSize;
	}

	/*
	
		Target Dump_Area -> Requester Copy
	
	*/
	PUCHAR DumpedAddress = NULL;
	VirtualAllocate(
		Requester__processInfo->ProcessHandle,
		Size,
		&DumpedAddress
	);


	SIZE_T returnBytes = 0;
	status = MmCopyVirtualMemory(
		Target__processInfo->ProcessObject,
		Start_Dump_Target_Address,

		Requester__processInfo->ProcessObject,
		DumpedAddress,
		Size,
		KernelMode,
		&returnBytes
	);
	//if (!NT_SUCCESS(status))
		//goto EXIT_1;


	output.Dumped_StartAddress = DumpedAddress;


	// dump struct -> Requester
	PUCHAR result_DumpedData = NULL;
	status = Kernel_Copy_2_Virtual(
		Requester__processInfo->ProcessId,
		(PUCHAR) & output,
		sizeof(output),
		&result_DumpedData
	);

	*DumpedData = (PMemDumpOutput)result_DumpedData;
	

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