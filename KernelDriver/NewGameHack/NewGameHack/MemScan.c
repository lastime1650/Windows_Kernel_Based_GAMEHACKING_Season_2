#include "MemScan.h"

#include "Process.h"
#include "API.h"

#include "VirtualMemory.h"

NTSTATUS NewScanning(
	_In_ HANDLE Requester_ProcessId,
	_In_ HANDLE Target_ProcessId,

	_In_ PUCHAR value,
	_In_ SIZE_T value_size,

	_Out_ PScanNode* ScannedStartNode // VirtualAlloc으로 할당된 메모리 주소
) {
	PProcess_info Requester_processInfo = NULL;
	PProcess_info Target_processInfo = NULL;



	NTSTATUS status = GetProcessInfoByProcessId(Requester_ProcessId, &Requester_processInfo);
	if (!NT_SUCCESS(status)) {
		goto EXIT_1;
	}

	
	status = GetProcessInfoByProcessId(Target_ProcessId, &Target_processInfo);
	if (!NT_SUCCESS(status)) {
		goto EXIT_1;
	}
	
	// init
	PUCHAR StartAddress = NULL;
	MEMORY_BASIC_INFORMATION memoryInfo = { 0, };

	PScanNode Requester__StartNode = NULL; // -> UserMode Address !!!!
	PScanNode Requester__CurrentNode = NULL; // -> UserMode Address !!!!


	// search Memory Page
	// * if StartAddress is NULL, it will start from the beginning address
	while (
		NT_SUCCESS(
			ZwQueryVirtualMemory(
				Target_processInfo->ProcessHandle, // Process Handle
				StartAddress, // Start Address
				MemoryBasicInformation, // MEM CLASS
				&memoryInfo, // Memory Basic Information
				sizeof(MEMORY_BASIC_INFORMATION), 
				NULL
			)
		)
	) {
		

		if (memoryInfo.Protect == PAGE_READWRITE && memoryInfo.State == MEM_COMMIT) {
			PUCHAR currentAddress = (PUCHAR)memoryInfo.BaseAddress;
			PUCHAR endAddress = currentAddress + memoryInfo.RegionSize;

			/*
			=======================================
			
				VALUE SCAN

			=======================================
			*/

			/*
				
				STEP 1: MEMCMP ( Value Match )
				STEP 2: if Match, Make the Linked List Node for Requester Process ( using VirtualAlloc )

				[ STEP2 -> BIGGEST WARNING ]
					-> Should be Freeing the Linked List Node after use In Requester Process ( UserMode )
				
			
			*/
			KAPC_STATE APC_STATE = { 0, };
			KeStackAttachProcess(Target_processInfo->ProcessObject, &APC_STATE);

			while (currentAddress < endAddress) {
				// STEP 1
				if (!MmIsAddressValid(currentAddress)) {
					// if Invalid VirtualAddress
					currentAddress = currentAddress + value_size;
					continue;
				}

				if (memcmp( value, currentAddress, value_size) == 0) {

					KeUnstackDetachProcess(&APC_STATE);

					KAPC_STATE Requester_APC_STATE = { 0, };
					KeStackAttachProcess(Requester_processInfo->ProcessObject, &Requester_APC_STATE);

					// STEP 2
					if (!Requester__StartNode) {

						VirtualAllocate(
							Requester_processInfo->ProcessHandle,
							sizeof(ScanNode),

							(PUCHAR*)&Requester__StartNode
						);

						((PScanNode)Requester__StartNode)->Detected_Address = currentAddress;
						((PScanNode)Requester__StartNode)->NextNode = NULL;

						Requester__CurrentNode = Requester__StartNode;
					}
					else {

						PUCHAR current_ = NULL;
						VirtualAllocate(
							Requester_processInfo->ProcessHandle,
							sizeof(ScanNode),

							& current_
						);

						Requester__CurrentNode->NextNode = current_;

						((PScanNode)current_)->Detected_Address = currentAddress;
						((PScanNode)current_)->NextNode = NULL;

						Requester__CurrentNode = (PScanNode)current_;
					}
					KeUnstackDetachProcess(&Requester_APC_STATE);
					
					KeStackAttachProcess(Target_processInfo->ProcessObject, &APC_STATE);
				}

				currentAddress = currentAddress + value_size; // Move to the next address
			}

			KeUnstackDetachProcess(&APC_STATE);
		}

		StartAddress = (PUCHAR)memoryInfo.BaseAddress + memoryInfo.RegionSize; // Update
	}

	*ScannedStartNode = Requester__StartNode;

EXIT_1:

	if (Requester_processInfo)
		ReleaseProcessInfo(Requester_processInfo); // Release the requester process info after use

	if (Target_processInfo)
		ReleaseProcessInfo(Target_processInfo); // Release the process info after use
	goto EXIT_0;
EXIT_0:
	return status;
}




NTSTATUS AddressScanning(
	_In_ HANDLE Requester_ProcessId,
	_In_ HANDLE Target_ProcessId,

	_In_ PUCHAR TargetProcessAddress, // 지정된 주소

	_In_ PUCHAR value,
	_In_ SIZE_T value_size,

	_Out_ PAddressScanned* ScannedAddress // VirtualAlloc으로 할당된 메모리 주소
) {
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	if (!ScannedAddress) {
		status = STATUS_INVALID_PARAMETER;
		goto EXIT0;
	}

	*ScannedAddress = NULL;

	PProcess_info Requester_processInfo = NULL;
	PProcess_info Target_processInfo = NULL;


	status = GetProcessInfoByProcessId(Requester_ProcessId, &Requester_processInfo);
	if (!NT_SUCCESS(status)) {
		goto EXIT_1;
	}

	
	status = GetProcessInfoByProcessId(Target_ProcessId, &Target_processInfo);
	if (!NT_SUCCESS(status)) {
		goto EXIT_1;
	}

	AddressScanned output = { 0, };

	KAPC_STATE APC_STATE = { 0, };
	KeStackAttachProcess(Target_processInfo->ProcessObject, &APC_STATE);

	if (!MmIsAddressValid(TargetProcessAddress)) {
		// CHeck VirtualAddress Valid 
		KeUnstackDetachProcess(&APC_STATE);
		goto EXIT_1;
	}

	if ( memcmp(TargetProcessAddress, value, value_size ) == 0 ) {
		output.is_same = TRUE;
	}
	else {
		output.is_same = FALSE;
	}

	KeUnstackDetachProcess(&APC_STATE);

	PUCHAR allocated_virtual = NULL;
	status = VirtualAllocate(
		Requester_processInfo->ProcessHandle,
		value_size,
		&allocated_virtual
	);
	if (!NT_SUCCESS(status)) {
		goto EXIT_1;
	}

	// target value -(copy)-> requester
	SIZE_T returnByte = 0;
	MmCopyVirtualMemory(
		Target_processInfo->ProcessObject,
		TargetProcessAddress,

		Requester_processInfo->ProcessObject,
		allocated_virtual,

		value_size,
		KernelMode,

		&returnByte
	);

	output.current_value = allocated_virtual;
	output.current_value_size = value_size;

	PUCHAR result = NULL;
	Kernel_Copy_2_Virtual(
		Requester_ProcessId,
		(PUCHAR) & output,
		sizeof(output),
		&result
	);

	*ScannedAddress = (PAddressScanned)result;


EXIT_1:
	if (Requester_processInfo)
		ReleaseProcessInfo(Requester_processInfo); // Release the requester process info after use

	if (Target_processInfo)
		ReleaseProcessInfo(Target_processInfo); // Release the process info after use

EXIT0:
	return status;
}



NTSTATUS AllScanning(
	_In_ HANDLE Requester_ProcessId,
	_In_ HANDLE Target_ProcessId,

	_In_ SIZE_T value_size,

	_Out_ PAllScannedNode* ScannedNodeAddr
) {
	NTSTATUS status = STATUS_UNSUCCESSFUL;

	if (!ScannedNodeAddr)
		goto EXIT_0;

	*ScannedNodeAddr = NULL;

	PProcess_info Requester_processInfo = NULL;
	PProcess_info Target_processInfo = NULL;


	status = GetProcessInfoByProcessId(Requester_ProcessId, &Requester_processInfo);
	if (!NT_SUCCESS(status)) {
		goto EXIT_1;
	}


	status = GetProcessInfoByProcessId(Target_ProcessId, &Target_processInfo);
	if (!NT_SUCCESS(status)) {
		goto EXIT_1;
	}

	PUCHAR StartAddress = NULL;
	MEMORY_BASIC_INFORMATION memoryInfo = { 0, };

	PAllScannedNode StartNodeAddress = NULL;
	PAllScannedNode CurrentNodeAddress = NULL;

	SIZE_T returnByte = 0;
	while (
		NT_SUCCESS(
			ZwQueryVirtualMemory(
				Target_processInfo->ProcessHandle, // Process Handle
				StartAddress, // Start Address
				MemoryBasicInformation, // MEM CLASS
				&memoryInfo, // Memory Basic Information
				sizeof(MEMORY_BASIC_INFORMATION),
				NULL
			)
		)
		) {


		if (memoryInfo.Protect == PAGE_READWRITE && memoryInfo.State == MEM_COMMIT) {
			PUCHAR currentAddress = (PUCHAR)memoryInfo.BaseAddress;
			PUCHAR endAddress = currentAddress + memoryInfo.RegionSize;

			KAPC_STATE Requester_APC_STATE = { 0, };
			KeStackAttachProcess(Requester_processInfo->ProcessObject, &Requester_APC_STATE);

			while (currentAddress <= endAddress) {

				
				

				/*
					Requester 에 노드 동적공간 할당
				*/
				PUCHAR allocated_virtual = NULL;
				status = VirtualAllocate(
					Requester_processInfo->ProcessHandle,
					value_size,
					&allocated_virtual
				);
				if (!NT_SUCCESS(status)) {
					currentAddress = (PUCHAR)currentAddress + value_size;
					continue;
				}


				/*
					TargetProcess -> Requester Copy
				*/
				status = MmCopyVirtualMemory(
					Target_processInfo->ProcessObject,
					currentAddress,

					Requester_processInfo->ProcessObject,
					allocated_virtual,

					value_size,
					KernelMode,

					&returnByte
				);
				if (!NT_SUCCESS(status)) {
					currentAddress = (PUCHAR)currentAddress + value_size;
					continue;
				}


				/*
					Requester 에 노드 데이터 생성
				*/
				if (!StartNodeAddress && !CurrentNodeAddress) {
					// NEW

					status = VirtualAllocate(
						Requester_processInfo->ProcessHandle,
						sizeof(AllScannedNode),
						(PUCHAR*) & StartNodeAddress
					);
					if (!NT_SUCCESS(status)) {
						currentAddress = (PUCHAR)currentAddress + value_size;
						continue;
					}

					StartNodeAddress->Target_Address = currentAddress;
					StartNodeAddress->value = allocated_virtual;
					StartNodeAddress->NextNode = NULL;

					CurrentNodeAddress = StartNodeAddress;
				}
				else {
					// UPDATE
					PAllScannedNode tmp_nodeaddr = NULL;
					status = VirtualAllocate(
						Requester_processInfo->ProcessHandle,
						sizeof(AllScannedNode),
						(PUCHAR*) & tmp_nodeaddr
					);
					if (!NT_SUCCESS(status)) {
						currentAddress = (PUCHAR)currentAddress + value_size;
						continue;
					}
					CurrentNodeAddress->NextNode = (PUCHAR)tmp_nodeaddr; // Connect 이어주기 이전 노드와,,

					tmp_nodeaddr->Target_Address = currentAddress;
					tmp_nodeaddr->value = allocated_virtual;
					tmp_nodeaddr->NextNode = NULL;

					CurrentNodeAddress = tmp_nodeaddr;
				}


				currentAddress = (PUCHAR)currentAddress + value_size;
			}

			KeUnstackDetachProcess(&Requester_APC_STATE);


		}

		StartAddress = (PUCHAR)memoryInfo.BaseAddress + memoryInfo.RegionSize; // Update
	}

	*ScannedNodeAddr = StartNodeAddress;


EXIT_1:
	if (Requester_processInfo)
		ReleaseProcessInfo(Requester_processInfo); // Release the requester process info after use

	if (Target_processInfo)
		ReleaseProcessInfo(Target_processInfo); // Release the process info after use

EXIT_0:
	return status;
}
