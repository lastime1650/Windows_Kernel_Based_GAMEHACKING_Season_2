#ifndef DUMP_STRUCT_H
#define DUMP_STRUCT_H

#include <ntifs.h>

typedef struct MemDumpOutput {

	PUCHAR Dumped_StartAddress; // need free if you done using

	/*
	
		페이지 정보
	
	*/
	PUCHAR Dumped_PAGE_BasedAddress; // need free if you done using


	PUCHAR PAGE_BaseAddress;
	SIZE_T PAGE_Size;
	
	ULONG32 PAGE_Protect;
	ULONG32 PAGE_State;
	 
}MemDumpOutput, * PMemDumpOutput;

typedef struct MemDump {

	HANDLE RequesterPID; // IOCTL 요청자 PID
	HANDLE TargetPID; // 타겟

	PUCHAR StartAddress; // 시작 주소
	SIZE_T Size; // 덤프할 크기


	PMemDumpOutput Output;
}MemDump, * PMemDump;

#endif