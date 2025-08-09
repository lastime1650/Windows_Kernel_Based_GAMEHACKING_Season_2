#include "IOCTL_ROUTINES.h"

NTSTATUS RequiredRoutine(PDEVICE_OBJECT pDeviceObject, PIRP Irp) {
	UNREFERENCED_PARAMETER(pDeviceObject);
	UNREFERENCED_PARAMETER(Irp);

	// NOTHING TO DO !!!!

	return STATUS_SUCCESS;
}

#include "Share_IOCTL.h" // IOCTL Code Definitions


#include "MemWrite.h"
#include "MemDump.h"
#include "HardwareBP.h"
#include "DLL_Injection.h"
#include "Scan.h"
#include "MemScan.h"
#include "VirtualMemory.h"

NTSTATUS IOCTLRoutine(PDEVICE_OBJECT pDeviceObject, PIRP Irp) {
	UNREFERENCED_PARAMETER(pDeviceObject);

	NTSTATUS status = STATUS_SUCCESS;
	PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(Irp); // Request Information

	

	// IOCTL_CODE TEST
	
	switch (irpSp->Parameters.DeviceIoControl.IoControlCode)
	{
		case IOCTL_NEWSCAN:
		{
			// *동적 테스트 완료

			/*
				Memory New Scan
			*/
			PNewScan Parameter = (PNewScan)Irp->AssociatedIrp.SystemBuffer; // Get System Buffer
			ULONG Parameter_Size = irpSp->Parameters.DeviceIoControl.InputBufferLength; // Get Input Buffer Length

			/*
			======================================================
				STEP 1: Requester Value(Virtual) to Kernel ( Copy )
				STEP 2: New-Scan
			======================================================
			*/


			PScanNode Scanning_Output = NULL;

			// STEP 1
			// Virtual Memory Value to Kernel
			// <Requester Value Data to Kernel>
			PUCHAR value_kernel = NULL;
			status = Virtual_Copy_2_Kernel(
				Parameter->RequesterPID, // Requester Process ID
				Parameter->value, // VIrtual Value
				Parameter->value_size, // Value Size 
				&value_kernel // Output Kernel Address
			);

			if (NT_SUCCESS(status) && value_kernel) {

				// STEP 2 
				status = NewScanning(
					Parameter->RequesterPID,
					Parameter->TargetPID, // Target Process ID to Scan

					value_kernel, // Value to Scan
					Parameter->value_size, // Size of Value to Scan

					&Scanning_Output // Output Scanned Address
				);
				
				Parameter->Output = Scanning_Output;

				Release_Virtual_Copy_2_Kernel(value_kernel); // Release Kernel Memory
			}

			
			Irp->IoStatus.Information = Parameter_Size;
			break;
		}
		case IOCTL_TARGETSCAN:
		{
			// *동적 테스트 완료
			/*
				Memory Target Scan
			*/

			PAddressScan Parameter = (PAddressScan)Irp->AssociatedIrp.SystemBuffer; // Get System Buffer
			ULONG Parameter_Size = irpSp->Parameters.DeviceIoControl.InputBufferLength; // Get Input Buffer Length

			/*
			======================================================
				STEP 1: Requester Value(Virtual) to Kernel ( Copy )
				STEP 2: Address-Scan
			======================================================
			*/



			// STEP 1
			// Virtual Memory Value to Kernel
			PUCHAR value_kernel = NULL;
			status = Virtual_Copy_2_Kernel(
				Parameter->RequesterPID, // Requester Process ID
				Parameter->value, // VIrtual Value
				Parameter->value_size, // Value Size 
				&value_kernel // Output Kernel Address
			);

			if (NT_SUCCESS(status) && value_kernel) {

				PAddressScanned Output = NULL;

				// STEP 2
				status = AddressScanning(
					Parameter->RequesterPID,
					Parameter->TargetPID, // Target Process ID to Scan

					Parameter->TargetAddress, // Target Address to Scan

					value_kernel, // Value to Scan
					Parameter->value_size, // Size of Value to Scan

					& Output // Output Scanned Address
				);

				Parameter->Output = Output;

				Release_Virtual_Copy_2_Kernel(value_kernel); // Release Kernel Memory
			}

			Irp->IoStatus.Status = status;
			Irp->IoStatus.Information = Parameter_Size;
			break;
		}

		case IOCTL_MEMDUMP:
		{
			// *동적 테스트 완료

			/*
				Memory Page Dump
			*/
			PMemDump Parameter = (PMemDump)Irp->AssociatedIrp.SystemBuffer; // Get System Buffer
			ULONG Parameter_Size = irpSp->Parameters.DeviceIoControl.InputBufferLength; // Get Input Buffer Length

			PMemDumpOutput OutputDump = NULL;
			MemDumping(
				Parameter->RequesterPID,
				Parameter->TargetPID,

				Parameter->StartAddress,
				Parameter->Size,

				& OutputDump
			);

			Parameter->Output = OutputDump;

			Irp->IoStatus.Status = status;
			Irp->IoStatus.Information = Parameter_Size;

			break;
		}
		case IOCTL_DLLINJECTION:
		{
			// *동적 테스트 완료
			/*
				Kernel Based DLL Injection
			*/
			PDLL_INJECTION_INPUT Parameter = (PDLL_INJECTION_INPUT)Irp->AssociatedIrp.SystemBuffer; // Get System Buffer
			ULONG Parameter_Size = irpSp->Parameters.DeviceIoControl.InputBufferLength; // Get Input Buffer Length

			status = DLL_Inject(
				Parameter->ProcessId, // Target Process ID
				Parameter->Injection_Dll_PATH // Dll Path to Inject
			);

			Parameter->Output = status; // Set Output Status

			Irp->IoStatus.Status = status;
			Irp->IoStatus.Information = Parameter_Size;

			break;
		}
		case IOCTL_HardwareBP:
		{
			// *동적 테스트 완료

			PHardware_Breakpoint Parameter = (PHardware_Breakpoint)Irp->AssociatedIrp.SystemBuffer; // Get System Buffer
			ULONG Parameter_Size = irpSp->Parameters.DeviceIoControl.InputBufferLength; // Get Input Buffer Length

			status = Set_Hardware_BreakPoint(
				Parameter->TargetPID,
				Parameter->TargetAddress,
				Parameter->is_remove
			);

			Parameter->Output = status;

			Irp->IoStatus.Status = status;
			Irp->IoStatus.Information = Parameter_Size;

			break;
		}
		case IOCTL_MEMWRITE:
		{
			// *동적 테스트 완료

			PMemWrite Parameter = (PMemWrite)Irp->AssociatedIrp.SystemBuffer; // Get System Buffer
			ULONG Parameter_Size = irpSp->Parameters.DeviceIoControl.InputBufferLength; // Get Input Buffer Length

			PUCHAR output = NULL;
			status = MemWriting(
				Parameter->RequesterPID,
				Parameter->TargetPID,
				Parameter->TargetAddress,
				Parameter->value,
				Parameter->value_size,
				Parameter->is_Protect_Change_Enable,
				&output
			);

			Parameter->Output = output;

			Irp->IoStatus.Status = status;
			Irp->IoStatus.Information = Parameter_Size;

			break;
		}
		case IOCTL_MEMALLSCAN:
		{
			PAllScan Parameter = (PAllScan)Irp->AssociatedIrp.SystemBuffer; // Get System Buffer
			ULONG Parameter_Size = irpSp->Parameters.DeviceIoControl.InputBufferLength; // Get Input Buffer Length
			
			PAllScannedNode output = NULL;
			status = AllScanning(
				Parameter->RequesterPID,
				Parameter->TargetPID,
				Parameter->value_size,
				&output
			);

			Parameter->Output = output;

			Irp->IoStatus.Status = status;
			Irp->IoStatus.Information = Parameter_Size;

			break;
		}
		default:
		{
			status = STATUS_INVALID_DEVICE_REQUEST; // Invalid IOCTL Code
			Irp->IoStatus.Status = status;
			Irp->IoStatus.Information = 0;
			break;
		}
	}
	
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return status;
}