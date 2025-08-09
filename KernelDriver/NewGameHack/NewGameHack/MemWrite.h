#ifndef MEMWRITE_H
#define MEMWRITE_H

#include <ntifs.h>
#include "Write.h"

NTSTATUS MemWriting(
	_In_ HANDLE Requester_ProcessId,
	_In_ HANDLE Target_ProecssId,

	_In_ PUCHAR TargetAddress, // 쓰기 대상 주소

	_In_ PUCHAR value_VirtualAddress, // 쓰기 데이터
	_In_ SIZE_T valueSize, // 쓰기 데이터 사이즈

	_In_ BOOLEAN is_Protect_Change_Enable, // 덮어쓰기전, 보호속성을 PAGE_EXECUTE_READWRITE로 강제 변환 후, COPY후 보호속성 복귀처리 

	_Out_ PUCHAR* Output // 덤프된 데이터 포인터 -> VirualAlloc으로 할당된 메모리 주소
);

#endif