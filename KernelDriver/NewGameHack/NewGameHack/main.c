#include <ntifs.h>


#include "API.h"

#include "New_main.h"

NTSTATUS
DriverEntry(
	_In_ PDRIVER_OBJECT DriverObject,
	_In_ PUNICODE_STRING RegistryPath
) {
	UNREFERENCED_PARAMETER(DriverObject);
	UNREFERENCED_PARAMETER(RegistryPath);
	/*
	
		[ Biggest Warning Message ]

		THis DriverEntry Arguments are not valid !!!! -> it means " NULL " 

		so you need to call "IoCreateDriver" API ^^ 
	
	*/

	// Init DriverName for creating a new driver object
	UNICODE_STRING DriverName = { 0, };
	
	RtlInitUnicodeString(
		&DriverName,
		L"\\Driver\\NewGameHack_" // Driver Name
	);


	return IoCreateDriver(
		&DriverName, // DriverName
		&NewDriverEntry // InitializationFunction -> THis is REAL !!!!! Entrypoint
	);
}