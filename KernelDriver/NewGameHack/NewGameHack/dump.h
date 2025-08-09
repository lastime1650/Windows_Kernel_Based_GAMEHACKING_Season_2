#ifndef DUMP_STRUCT_H
#define DUMP_STRUCT_H

#include <ntifs.h>

typedef struct MemDumpOutput {

	PUCHAR Dumped_StartAddress; // need free if you done using

	/*
	
		������ ����
	
	*/
	PUCHAR Dumped_PAGE_BasedAddress; // need free if you done using


	PUCHAR PAGE_BaseAddress;
	SIZE_T PAGE_Size;
	
	ULONG32 PAGE_Protect;
	ULONG32 PAGE_State;
	 
}MemDumpOutput, * PMemDumpOutput;

typedef struct MemDump {

	HANDLE RequesterPID; // IOCTL ��û�� PID
	HANDLE TargetPID; // Ÿ��

	PUCHAR StartAddress; // ���� �ּ�
	SIZE_T Size; // ������ ũ��


	PMemDumpOutput Output;
}MemDump, * PMemDump;

#endif