#ifndef SCAN_H
#define SCAN_H

#include <ntifs.h>

#include "Scan.h"

NTSTATUS NewScanning(
	_In_ HANDLE Requester_ProcessId,
	_In_ HANDLE Target_ProcessId,

	_In_ PUCHAR value,
	_In_ SIZE_T value_size,

	_Out_ PScanNode* ScannedStartNode // VirtualAlloc���� �Ҵ�� �޸� �ּ�
);

NTSTATUS AddressScanning(
	_In_ HANDLE Requester_ProcessId,
	_In_ HANDLE Target_ProcessId,

	_In_ PUCHAR TargetProcessAddress, // ������ �ּ�

	_In_ PUCHAR value,
	_In_ SIZE_T value_size,

	_Out_ PAddressScanned* ScannedAddress // VirtualAlloc���� �Ҵ�� �޸� �ּ�
);

NTSTATUS AllScanning(
	_In_ HANDLE Requester_ProcessId,
	_In_ HANDLE Target_ProcessId,

	_In_ SIZE_T value_size,

	_Out_ PAllScannedNode* ScannedNodeAddr
);

#endif