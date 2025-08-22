#ifndef PROCESSMONITOR_H
#define PROCESSMONITOR_H
#include <ntifs.h>
#include <intrin.h>
#define CR3_64BIT_ADDRESS_OFFSET 0x28

typedef struct ProcessMon {

	HANDLE ProcessId;
	UINT64 CR3;

	PUCHAR NextAddress;

}ProcessMon, *PProcessMon;

extern PProcessMon ProcessMon_StartNodeAddr;
extern PProcessMon ProcessMon_CurrentNodeAddr;

#define ProcessMon_Allocate_TAG 'PMAT' // ProcessMon Allocate Tag

//UINT64 Extract_CR3_from_process(PEPROCESS Process);
BOOLEAN Save_To_ProcessMonNode(PEPROCESS Process);

/*
PProcessMon CreateProcessMonNode(HANDLE ProcessId, PUCHAR CR3);
PProcessMon AppendProcessMonNode(PProcessMon currentNode, HANDLE ProcessId, PUCHAR CR3);
*/
VOID PrintALLProcessMon();
PProcessMon SearchProcessMonNode(HANDLE ProcessId);
VOID Remove_One_ProcessNode(PEPROCESS Process);
VOID RemoveALLProcessNode();


#endif