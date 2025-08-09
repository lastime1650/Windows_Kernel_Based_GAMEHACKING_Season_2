#include "New_main.h"

#include "DeviceCreate.h" // IOCTL 디바이스 생성 헤더

#include "IOCTL_ROUTINES.h"

PDEVICE_OBJECT DeviceObject = NULL; // Global Device Object for IOCTL

NTSTATUS
DriverUnload(
	_In_ PDRIVER_OBJECT DriverObject
); // Unload


NTSTATUS
NewDriverEntry(
	_In_ PDRIVER_OBJECT DriverObject,
	_In_ PUNICODE_STRING RegistryPath
) {
	UNREFERENCED_PARAMETER(RegistryPath); // Unused Parameter
	NTSTATUS status = STATUS_SUCCESS;

	/*
	
		Create Own Device for IOCTL with Usermode ^^
	
	*/

	// STEP 1) Create Device Object for IOCTL
	DeviceObject = CreateDevice(DriverObject);
	if (!DeviceObject)
		return STATUS_UNSUCCESSFUL;

	// STEP 2) Set Driver Unload
	DriverObject->DriverUnload = DriverUnload; // Set Unload Routine


	// STEP 3) Set DriverObject Dispatch Routines
	DriverObject->MajorFunction[IRP_MJ_CREATE] = RequiredRoutine; // Just required ..
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = RequiredRoutine; // Just required ..

	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = IOCTLRoutine; // IOCTL ! 

	// Final STEP) Set Activation Device
	DeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

	DbgPrintEx(
		DPFLTR_IHVDRIVER_ID, 
		DPFLTR_WARNING_LEVEL, 
		" SUCCESS ! \n"
	);

	return status;
}

NTSTATUS
DriverUnload(
	_In_ PDRIVER_OBJECT DriverObject
) {
	UNREFERENCED_PARAMETER(DriverObject);
	NTSTATUS status;

	// Delete Device Object
	status = DeleteDevice(
		DeviceObject
	);

	return status;
}