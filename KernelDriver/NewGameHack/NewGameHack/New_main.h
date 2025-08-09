#ifndef NEW_MAIN_H
#define NEW_MAIN_H

#include <ntifs.h>

NTSTATUS
NewDriverEntry(
	_In_ PDRIVER_OBJECT DriverObject,
	_In_ PUNICODE_STRING RegistryPath
);


#endif