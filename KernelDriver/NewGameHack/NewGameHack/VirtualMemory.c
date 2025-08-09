#pragma warning(disable:4996)
#include "VirtualMemory.h"

NTSTATUS VirtualAllocate(
	_In_ HANDLE ProcessHandle,
	_In_ SIZE_T Size,

	_Inout_ PUCHAR* StartAddress
) {
	if (!StartAddress)
		return STATUS_INVALID_PARAMETER;

	NTSTATUS status = ZwAllocateVirtualMemory(
		ProcessHandle,
		(PVOID*)StartAddress,
		0,
		&Size,
		MEM_COMMIT,
		PAGE_READWRITE
	);

	if (!NT_SUCCESS(status)) {
		*StartAddress = NULL; // FAILED
		return status;
	}

	return status;
}

#include "Process.h"
#include "API.h"

NTSTATUS Virtual_Copy_2_Kernel(
	_In_ HANDLE ProcessId,


	_In_ PUCHAR VirtualDataAddress,
	_In_ SIZE_T DataSize,

	_Out_ PUCHAR* KernelDataAddress // VirtualAlloc으로 할당된 메모리 주소
) {
	if (!KernelDataAddress || !VirtualDataAddress)
		return STATUS_INVALID_PARAMETER;

	PProcess_info ProcessInfo = NULL;
	NTSTATUS status = GetProcessInfoByProcessId(ProcessId, &ProcessInfo);

	if (!ProcessInfo)
		return status; // Failed to get process info

	PEPROCESS systemprocess = PsGetCurrentProcess(); // SYSTEM.exe ( if not USERMODE context ) 

	*KernelDataAddress = (PUCHAR)ExAllocatePoolWithTag(
		NonPagedPool,
		DataSize,
		'Vmem' // Tag for memory allocation
	);

	SIZE_T return_size = 0;
	status = MmCopyVirtualMemory(

		ProcessInfo->ProcessObject, // Target Process (Target Process Object)
		VirtualDataAddress, // Target Address (Kernel Mode Address)

		systemprocess, // Source Process (SYSTEM)
		* KernelDataAddress, // Source Address (User Mode Address)
		
		DataSize, // Size of data to copy
		KernelMode, // Source mode
		& return_size // Status

	);

	ReleaseProcessInfo(ProcessInfo);
	return status;

}

VOID Release_Virtual_Copy_2_Kernel(
	_In_ PUCHAR KernelDataAddress
)
{
	if (KernelDataAddress) {
		ExFreePoolWithTag(KernelDataAddress, 'Vmem'); // Free the allocated memory
	}
}



NTSTATUS Kernel_Copy_2_Virtual(
	_In_ HANDLE ProcessId,

	_In_ PUCHAR KernelDataAddress,
	_In_ SIZE_T DataSize,

	_Out_ PUCHAR* VirtualDataAddress // VirtualAlloc으로 할당된 메모리 주소
) {
	if (!KernelDataAddress || !VirtualDataAddress)
		return STATUS_INVALID_PARAMETER;

	PProcess_info ProcessInfo = NULL;
	NTSTATUS status = GetProcessInfoByProcessId(ProcessId, &ProcessInfo);

	if (!ProcessInfo)
		return status; // Failed to get process info



	// Alloc to Virtual
	PUCHAR AllocatedVirtualAddress = NULL;
	status = VirtualAllocate(
		ProcessInfo->ProcessHandle, // Target Process Handle
		DataSize, // Size of data to allocate
		&AllocatedVirtualAddress // Address to store the allocated memory
	);
	if (!NT_SUCCESS(status)) {
		ReleaseProcessInfo(ProcessInfo);
		return status; // Failed to allocate virtual memory
	}





	PEPROCESS systemprocess = PsGetCurrentProcess(); // SYSTEM.exe ( if not USERMODE context ) 

	SIZE_T return_size = 0;
	status = MmCopyVirtualMemory(


		systemprocess, // Source Process (SYSTEM)
		KernelDataAddress, // Source Address (User Mode Address)

		ProcessInfo->ProcessObject, // Target Process (Target Process Object)
		AllocatedVirtualAddress, // Target Address (Kernel Mode Address)

		DataSize, // Size of data to copy
		KernelMode, // Source mode
		&return_size // Status

	);

	*VirtualDataAddress = AllocatedVirtualAddress; // Set the allocated virtual address

	ReleaseProcessInfo(ProcessInfo);
	return status;
}

