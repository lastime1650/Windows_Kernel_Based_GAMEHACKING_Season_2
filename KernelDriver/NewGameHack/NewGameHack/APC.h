#pragma warning(disable:4996)
#ifndef APC_H
#include <ntifs.h>
#include "API.h"
typedef struct _APC {

	HANDLE ThreadID;
	PVOID User_APCHandler;

}APC, * PAPC;

#define APC_ALLOC_TAG 'APCu'

extern PETHREAD USER_Thread; 
extern PKNORMAL_ROUTINE USER_APC_HANDLER;

NTSTATUS INITIALIZE_APC(HANDLE USER_ThreadID, PVOID USER_APC_Handler);

BOOLEAN ApcToUser(ULONG64 cmd, PVOID UserAllocatedData);// insert APC queue

VOID Terminate_APC( _In_opt_ PKAPC APC );

#endif