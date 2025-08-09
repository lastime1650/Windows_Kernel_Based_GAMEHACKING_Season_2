#ifndef MEM_DUMP_H
#define MEM_DUMP_H

#include <ntifs.h>

#include "dump.h"

NTSTATUS MemDumping(
	_In_ HANDLE Requester_ProcessId,
	_In_ HANDLE Target_ProecssId,

	_In_ PUCHAR StartAddress, // 시작 주소
	_In_ SIZE_T Size, // 덤프할 크기

	_Out_ PMemDumpOutput* DumpedData // 덤프된 데이터 포인터 -> VirualAlloc으로 할당된 메모리 주소 ( Requester Heap address  ) 
);


#endif