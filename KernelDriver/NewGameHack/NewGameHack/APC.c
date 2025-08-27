#include "APC.h"
#include "API.h"

#include <intrin.h>

PETHREAD USER_Thread = NULL;
PKNORMAL_ROUTINE USER_APC_HANDLER = NULL;

VOID NTAPI KernelApcCleanup(PKAPC Apc, PKNORMAL_ROUTINE* NormalRoutine, PVOID* NormalContext, PVOID* SystemArgument1, PVOID* SystemArgument2);

NTSTATUS INITIALIZE_APC(HANDLE USER_ThreadID, PVOID USER_APC_Handler)
{
	NTSTATUS status;

	status = PsLookupThreadByThreadId(USER_ThreadID, &USER_Thread);
	if (!NT_SUCCESS(status))
		return status;

	USER_APC_HANDLER = (PKNORMAL_ROUTINE)USER_APC_Handler;

	// 삽입 테스트 ( 3번 진행 )
	if (!ApcToUser( (ULONG64)1, (PVOID)1) )
	{
		Terminate_APC(NULL);
		return STATUS_UNSUCCESSFUL;
	}
	if (!ApcToUser((ULONG64)2, (PVOID)2))
	{
		Terminate_APC(NULL);
		return STATUS_UNSUCCESSFUL;
	}
	if (!ApcToUser((ULONG64)3, (PVOID)3))
	{
		Terminate_APC(NULL);
		return STATUS_UNSUCCESSFUL;
	}

	return status;
}

// 비동기적으로 유저모드에게 전달할 때, ( APC )
BOOLEAN ApcToUser(ULONG64 cmd, PVOID UserAllocatedData)
{
	PKAPC Response_APC = ExAllocatePoolWithTag(NonPagedPool, sizeof(KAPC), APC_ALLOC_TAG);
	if (!Response_APC)
	{
		ObfDereferenceObject(USER_Thread);
		return FALSE;
	}

	KeInitializeApc(
		Response_APC,
		USER_Thread,
		OriginalApcEnvironment,
		KernelApcCleanup,
		NULL,
		(PKNORMAL_ROUTINE)USER_APC_HANDLER, // USER ADDRESS CALLBACK ! 
		UserMode,
		NULL // 유저모드 APC 콜백함수에 전달할 것 ( Argument 1 )
	);

	if (!KeInsertQueueApc(
		Response_APC,
		(PVOID)cmd,// 그대로 삽입
		UserAllocatedData, // 크기는 cmd에 정해진 구조체로 캐스팅하도록 설계됨
		0 )
	) {
		ExFreePoolWithTag(Response_APC, APC_ALLOC_TAG);
		return FALSE;
	}

	return TRUE;
}

VOID Terminate_APC(PKAPC APC) {
	if (APC)
		ExFreePoolWithTag(APC, APC_ALLOC_TAG);
	if (USER_Thread)
		ObfDereferenceObject(USER_Thread);
}


VOID NTAPI KernelApcCleanup(PKAPC Apc, PKNORMAL_ROUTINE* NormalRoutine, PVOID* NormalContext, PVOID* SystemArgument1, PVOID* SystemArgument2)
{
	UNREFERENCED_PARAMETER(NormalRoutine);
	UNREFERENCED_PARAMETER(NormalContext);
	UNREFERENCED_PARAMETER(SystemArgument1);
	UNREFERENCED_PARAMETER(SystemArgument2);

	// KeInsertQueueApc가 사용한 APC 객체를 해제합니다.
	ExFreePoolWithTag(Apc, APC_ALLOC_TAG);
}
