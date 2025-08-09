#ifndef DLL_INJECTION_H
#define DLL_INJECTION_H

#include <ntifs.h>

#include "DLLInjection.h"

NTSTATUS DLL_Inject(

	_In_ HANDLE ProcessId, // Target Process ID

	_In_ PCHAR Injection_Dll_PATH // Hacking Dll Path
);


#endif