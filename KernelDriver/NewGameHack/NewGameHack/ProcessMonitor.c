#include "ProcessMonitor.h"
#include "KEVENT_or_KMUTEX_init.h"


PProcessMon ProcessMon_StartNodeAddr = NULL;
PProcessMon ProcessMon_CurrentNodeAddr = NULL;

K_EVENT_or_MUTEX_struct ProcessMonMutex = { NULL, K_MUTEX, FALSE };

// K_object_init_check_also_lock_ifyouwant(&ProcessMonMutex, TRUE);
// K_object_lock_Release(&ProcessMonMutex);


/*
	CR3 Extract and Save to Linked List
*/
UINT64 Extract_CR3_from_process(PEPROCESS Process) {

	// CR3
	UINT64 CR3 = *(PUINT64)((PUCHAR)Process + CR3_64BIT_ADDRESS_OFFSET);

	/*
		1: kd> g
			CR3 -> 000000017129C000 
			CR3 -> 00000001761A2000 
			CR3 -> 000000016196C000 
			CR3 -> 000000013F046000 
			CR3 -> 000000016DFC7000 
			CR3 -> 000000016CFE3000 
			CR3 -> 000000013F3F8000 
	
	
	DbgPrintEx(
		DPFLTR_IHVDRIVER_ID,
		DPFLTR_ERROR_LEVEL,
		" CR3 -> %p \n", CR3
	);
	*/

	return CR3;
}

PProcessMon CreateProcessMonNode(HANDLE ProcessId, UINT64 CR3) {

	PProcessMon Node = ExAllocatePoolWithTag(NonPagedPool, sizeof(ProcessMon), ProcessMon_Allocate_TAG);
	if (!Node)
		return NULL;

	Node->ProcessId = ProcessId;
	Node->CR3 = CR3;
	Node->NextAddress = NULL;

	return Node;

}
PProcessMon AppendProcessMonNode(PProcessMon currentNode, HANDLE ProcessId, UINT64 CR3) {
	if (!currentNode)
		return NULL;

	PProcessMon NewNode = CreateProcessMonNode(ProcessId, CR3);
	if (!NewNode)
		return currentNode;// FAILED

	
	currentNode->NextAddress = (PUCHAR)NewNode;
	
	return NewNode;
}
PProcessMon SearchProcessMonNode(HANDLE ProcessId) {
	K_object_init_check_also_lock_ifyouwant(&ProcessMonMutex, TRUE);

	if (!ProcessMon_StartNodeAddr || ProcessId == 0) {
		K_object_lock_Release(&ProcessMonMutex);
		return NULL;
	}
		
	PProcessMon current = ProcessMon_StartNodeAddr;
	while (current) {

		if (current->ProcessId == ProcessId) {
			K_object_lock_Release(&ProcessMonMutex);
			return current;
		}
			

		current = (PProcessMon)current->NextAddress;
	}
	K_object_lock_Release(&ProcessMonMutex);
	return NULL;
}
VOID Remove_One_ProcessNode(PEPROCESS Process) {
	K_object_init_check_also_lock_ifyouwant(&ProcessMonMutex, TRUE);

	if (!ProcessMon_StartNodeAddr || !Process){
		K_object_lock_Release(&ProcessMonMutex);
		return;
	}

	HANDLE ProcessId = PsGetProcessId(Process);

	PProcessMon current = ProcessMon_StartNodeAddr;
	PProcessMon previous = NULL;
	while (current) {

		if (current->ProcessId == ProcessId) {
			if (previous) {
				previous->NextAddress = current->NextAddress;
				if (ProcessMon_CurrentNodeAddr == current)
					if (current->NextAddress == NULL) {
						ProcessMon_CurrentNodeAddr = previous;
					}
			}
			else {
				ProcessMon_StartNodeAddr = (PProcessMon)current->NextAddress;
				ProcessMon_CurrentNodeAddr = ProcessMon_StartNodeAddr;
			}
			ExFreePoolWithTag(current, ProcessMon_Allocate_TAG);

			K_object_lock_Release(&ProcessMonMutex);
			return;
		}

		previous = current;
		current = (PProcessMon)current->NextAddress;
	}
	K_object_lock_Release(&ProcessMonMutex);
	return;

}
VOID RemoveALLProcessNode() {

	K_object_init_check_also_lock_ifyouwant(&ProcessMonMutex, TRUE);

	if (!ProcessMon_StartNodeAddr) {
		K_object_lock_Release(&ProcessMonMutex);
		return;
	}
		

	PProcessMon current = ProcessMon_StartNodeAddr;
	while (current) {

		PProcessMon NextNode = (PProcessMon)current->NextAddress;
		ExFreePoolWithTag(current, ProcessMon_Allocate_TAG);


		current = NextNode;
	}
	ProcessMon_StartNodeAddr = NULL;
	ProcessMon_CurrentNodeAddr = NULL;

	K_object_lock_Release(&ProcessMonMutex);
}

VOID PrintALLProcessMon() {
	K_object_init_check_also_lock_ifyouwant(&ProcessMonMutex, TRUE);
	PProcessMon current = ProcessMon_StartNodeAddr;
	while (current) {

		DbgPrintEx(
			DPFLTR_IHVDRIVER_ID,
			DPFLTR_ERROR_LEVEL,
			" [ PID: %d, CR3: %p ] \n", current->ProcessId, current->CR3 
		);


		current = (PProcessMon)current->NextAddress;
	}
	K_object_lock_Release(&ProcessMonMutex);
}









BOOLEAN Save_To_ProcessMonNode(PEPROCESS Process) {
	if (!Process)
		return FALSE;

	HANDLE ProcessId = PsGetProcessId(Process);
	if (ProcessId < (HANDLE)100)
		return FALSE;

	// CR3
	UINT64 CR3 = Extract_CR3_from_process(Process);

	K_object_init_check_also_lock_ifyouwant(&ProcessMonMutex, TRUE);
	if (!ProcessMon_StartNodeAddr) {
		ProcessMon_StartNodeAddr = CreateProcessMonNode(ProcessId, CR3);
		ProcessMon_CurrentNodeAddr = ProcessMon_StartNodeAddr;
	}
	else {
		ProcessMon_CurrentNodeAddr = AppendProcessMonNode(ProcessMon_CurrentNodeAddr, ProcessId, CR3);
	}
	K_object_lock_Release(&ProcessMonMutex);
	return  TRUE;
}