#ifndef HWBP_H
#define HWBP_H

#include <ntifs.h>

#include "Hardware_BP.h"

NTSTATUS Set_Hardware_BreakPoint(
	HANDLE ProcessId,
	PUCHAR TargetAddress,
	BOOLEAN isRemove
);

#endif