#ifndef IOCTL_ROUTINES_H
#define IOCTL_ROUTINES_H

#include <ntifs.h>



// Required ROutines for working IOCTL
// 1. IRP_MJ_CREATE
// 2. IRP_MJ_CLOSE
NTSTATUS RequiredRoutine(PDEVICE_OBJECT pDeviceObject, PIRP Irp); 


// 3. IRP_MJ_DEVICE_CONTROL ( Essential for IOCTL )
NTSTATUS IOCTLRoutine(PDEVICE_OBJECT pDeviceObject, PIRP Irp);


#endif