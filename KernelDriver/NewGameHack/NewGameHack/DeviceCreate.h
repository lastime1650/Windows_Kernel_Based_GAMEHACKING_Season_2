#ifndef DEVICE_CREATE_H
#define DEVICE_CREATE_H

#include <ntifs.h>

/*
	Device name,
	Symbol name,
*/
#define DEVICE_NAME L"\\Device\\NewGameHack"
#define SYMBOLIC_NAME L"\\??\\NewGameHack"


PDEVICE_OBJECT CreateDevice(
	_In_ PDRIVER_OBJECT DriverObject
);

NTSTATUS DeleteDevice(
	_In_ PDEVICE_OBJECT DeviceObject
);

#endif