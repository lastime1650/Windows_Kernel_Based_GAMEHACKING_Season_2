#ifndef HardwareBP_H
#define HardwareBP_H

#include <ntifs.h>

typedef struct Hardware_Breakpoint {
	
	BOOLEAN is_remove; // if TRUE, remove. if FALSE, add

	HANDLE TargetPID;
	PUCHAR TargetAddress;

	NTSTATUS Output;

}Hardware_Breakpoint, *PHardware_Breakpoint;

#endif