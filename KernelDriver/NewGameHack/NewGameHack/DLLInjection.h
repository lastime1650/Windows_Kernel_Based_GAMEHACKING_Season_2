#ifndef Share_DLL_INJECTION_H
#define Share_DLL_INJECTION_H

#include <ntifs.h>


typedef struct DLL_INJECTION_IOCTL {
	HANDLE ProcessId; // Target Process ID
	CHAR Injection_Dll_PATH[265]; // DLL PATH ( ANSI ) 



	NTSTATUS Output; // output status
	
} DLL_INJECTION_INPUT, * PDLL_INJECTION_INPUT;

#endif