#ifndef MEM_DUMP_H
#define MEM_DUMP_H

#include <ntifs.h>

#include "dump.h"

NTSTATUS MemDumping(
	_In_ HANDLE Requester_ProcessId,
	_In_ HANDLE Target_ProecssId,

	_In_ PUCHAR StartAddress, // ���� �ּ�
	_In_ SIZE_T Size, // ������ ũ��

	_Out_ PMemDumpOutput* DumpedData // ������ ������ ������ -> VirualAlloc���� �Ҵ�� �޸� �ּ� ( Requester Heap address  ) 
);


#endif