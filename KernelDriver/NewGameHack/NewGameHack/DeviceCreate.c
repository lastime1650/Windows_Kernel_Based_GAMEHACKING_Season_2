#include "DeviceCreate.h"

PDEVICE_OBJECT CreateDevice(
	_In_ PDRIVER_OBJECT DriverObject
) {
	if (!DriverObject)
		return NULL;

	PDEVICE_OBJECT DeviceObject = NULL;
	UNICODE_STRING DeviceName;
	UNICODE_STRING SymbolicLinkName;
	NTSTATUS status;

	RtlInitUnicodeString(&DeviceName, DEVICE_NAME);
	RtlInitUnicodeString(&SymbolicLinkName, SYMBOLIC_NAME);

	status = IoCreateDevice(
		DriverObject,
		0,
		&DeviceName,
		FILE_DEVICE_UNKNOWN,
		FILE_DEVICE_SECURE_OPEN,
		FALSE,
		&DeviceObject
	);

	if (NT_SUCCESS(status)) {
		status = IoCreateSymbolicLink(&SymbolicLinkName, &DeviceName);
		if (!NT_SUCCESS(status)) {
			IoDeleteDevice(DeviceObject);
			return NULL;
		}
	}

	return DeviceObject;
}


NTSTATUS DeleteDevice(
	_In_ PDEVICE_OBJECT DeviceObject
) {
	if (!DeviceObject)
		return STATUS_INVALID_PARAMETER;

	UNICODE_STRING SymbolicLinkName;
	RtlInitUnicodeString(&SymbolicLinkName, SYMBOLIC_NAME);

	IoDeleteSymbolicLink(&SymbolicLinkName);
	IoDeleteDevice(DeviceObject);

	return STATUS_SUCCESS;
}