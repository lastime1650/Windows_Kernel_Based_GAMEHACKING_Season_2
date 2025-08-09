#ifndef VTMEM_H
#define VTMEM_H

#include <ntifs.h>

// Allocate
NTSTATUS VirtualAllocate(
	_In_ HANDLE ProcessHandle,
	_In_ SIZE_T Size,

	_Inout_ PUCHAR* StartAddress
);

// Copy -> Virtual to Kernel
NTSTATUS Virtual_Copy_2_Kernel(
	_In_ HANDLE ProcessId,


	_In_ PUCHAR VirtualDataAddress,
	_In_ SIZE_T DataSize,

	_Out_ PUCHAR* KernelDataAddress // VirtualAlloc으로 할당된 메모리 주소
);

VOID Release_Virtual_Copy_2_Kernel(
	_In_ PUCHAR KernelDataAddress
);

NTSTATUS Kernel_Copy_2_Virtual(
	_In_ HANDLE ProcessId,

	_In_ PUCHAR KernelDataAddress,
	_In_ SIZE_T DataSize,

	_Out_ PUCHAR* VirtualDataAddress // VirtualAlloc으로 할당된 메모리 주소
);

#endif