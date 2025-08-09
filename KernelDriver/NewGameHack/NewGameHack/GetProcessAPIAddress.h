#ifndef GPAA_H
#define GPAA_H

#include "PE_logic.h"

typedef struct Got_UserThread_APIs {

	PVOID SuspendThread_Address;
	PVOID ResumeThread_Address;
	/*
	
	...
	추가가능

	*/

}Got_UserThread_APIs, *PGot_UserThread_APIs;

NTSTATUS Get_ALL_APIS(HANDLE ProcessId, Got_UserThread_APIs* output);

NTSTATUS Get_SuspendThread_Address(HANDLE Processid, PUCHAR* Dll_Base_VirtualAddress, PUCHAR* API_Base_VirtualAddress);
NTSTATUS Get_ResumeThread_Address(HANDLE Processid, PUCHAR* Dll_Base_VirtualAddress, PUCHAR* API_Base_VirtualAddress);

NTSTATUS Call_2_User_Thread(HANDLE ProcessHandle, PVOID UserThreadAddress, PVOID Parameter, HANDLE* return_HANDLE);

#endif