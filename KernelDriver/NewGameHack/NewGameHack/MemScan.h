#ifndef SCAN_H
#define SCAN_H

#include <ntifs.h>

#include "Scan.h"

NTSTATUS NewScanning(
	_In_ HANDLE Requester_ProcessId,
	_In_ HANDLE Target_ProcessId,

	_In_ PUCHAR value,
	_In_ SIZE_T value_size,

	_Out_ PScanNode* ScannedStartNode // VirtualAlloc으로 할당된 메모리 주소
);

NTSTATUS AddressScanning(
	_In_ HANDLE Requester_ProcessId,
	_In_ HANDLE Target_ProcessId,

	_In_ PUCHAR TargetProcessAddress, // 지정된 주소

	_In_ PUCHAR value,
	_In_ SIZE_T value_size,

	_Out_ PAddressScanned* ScannedAddress // VirtualAlloc으로 할당된 메모리 주소
);

NTSTATUS AllScanning(
	_In_ HANDLE Requester_ProcessId,
	_In_ HANDLE Target_ProcessId,

	_In_ SIZE_T value_size,

	_Out_ PAllScannedNode* ScannedNodeAddr
);

#endif