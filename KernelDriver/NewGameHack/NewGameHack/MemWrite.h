#ifndef MEMWRITE_H
#define MEMWRITE_H

#include <ntifs.h>
#include "Write.h"

NTSTATUS MemWriting(
	_In_ HANDLE Requester_ProcessId,
	_In_ HANDLE Target_ProecssId,

	_In_ PUCHAR TargetAddress, // ���� ��� �ּ�

	_In_ PUCHAR value_VirtualAddress, // ���� ������
	_In_ SIZE_T valueSize, // ���� ������ ������

	_In_ BOOLEAN is_Protect_Change_Enable, // �������, ��ȣ�Ӽ��� PAGE_EXECUTE_READWRITE�� ���� ��ȯ ��, COPY�� ��ȣ�Ӽ� ����ó�� 

	_Out_ PUCHAR* Output // ������ ������ ������ -> VirualAlloc���� �Ҵ�� �޸� �ּ�
);

#endif