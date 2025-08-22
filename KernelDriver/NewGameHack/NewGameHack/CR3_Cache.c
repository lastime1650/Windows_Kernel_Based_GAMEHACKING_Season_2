#include "CR3_Cache.h"

PCR3_CACHE CR3_STARTNODE = NULL;
PCR3_CACHE CR3_CURRENTNODE = NULL;

FAST_MUTEX cr3_mutex = { 0 };


VOID Init_CR3() {
	CR3_STARTNODE = NULL;
	CR3_CURRENTNODE = NULL;

	// Initialize the mutex
	ExInitializeFastMutex(&cr3_mutex);
}


PCR3_CACHE CreateProcessMonNode(HANDLE ProcessId, UINT64 CR3);
PCR3_CACHE AppendProcessMonNode(PCR3_CACHE currentNode, HANDLE ProcessId, UINT64 CR3);
PCR3_CACHE SearchCR3Node(HANDLE ProcessId);

UINT64 Extract_CR3(PEPROCESS Process) {

	// CR3
	UINT64 CR3 = *(PUINT64)((PUCHAR)Process + CR3_64BIT_ADDRESS_OFFSET);
	return CR3;
}

BOOLEAN SaveCR3(_In_ PEPROCESS Process) {

	HANDLE ProcessId = PsGetProcessId(Process);

	if (!Process || ProcessId <= (HANDLE)300) {
		return FALSE; // Invalid process or process ID
	}

	UINT64 CR3 = Extract_CR3(Process);

	ExAcquireFastMutex(&cr3_mutex);
	if (!CR3_STARTNODE) {
		CR3_STARTNODE = CreateProcessMonNode(ProcessId, CR3);
		CR3_CURRENTNODE = CR3_STARTNODE;
	}
	else {
		CR3_CURRENTNODE = AppendProcessMonNode(CR3_CURRENTNODE, ProcessId, CR3);
	}
	ExReleaseFastMutex(&cr3_mutex);
	return TRUE;
}
VOID RemoveCR3(_In_ PEPROCESS Process) {

	HANDLE ProcessId = PsGetProcessId(Process);
	if (!Process || ProcessId <= (HANDLE)300) {
		return; // Invalid process or process ID
	}

	ExAcquireFastMutex(&cr3_mutex);
	if (!CR3_STARTNODE || ProcessId == 0) {
		ExReleaseFastMutex(&cr3_mutex);
		return ;
	}

	PCR3_CACHE current = CR3_STARTNODE;
	PCR3_CACHE previous = NULL;

	while (current) {
		if (current->ProcessId == ProcessId) {
			if (previous) {
				previous->NextNode = current->NextNode;
			}
			else {
				CR3_STARTNODE = current->NextNode; // Remove the first node
			}

			if (current == CR3_CURRENTNODE) {
				CR3_CURRENTNODE = previous; // Update the current node if it was the last one
			}

			ExFreePoolWithTag(current, CR3_CACHE_TAG);
			break;
		}
		previous = current;
		current = current->NextNode;
	}

	ExReleaseFastMutex(&cr3_mutex);
}


UINT64 Get_CR3(PEPROCESS process){
	if (!process) {
		return 0; // Invalid process
	}

	// Get the CR3 value for the process
	HANDLE ProcessId = PsGetProcessId(process);
	PCR3_CACHE cr3_cache = SearchCR3Node(ProcessId);
	if (!cr3_cache) {
		return 0; // CR3 not found for the process
	}

	return cr3_cache->CR3;
}

PCR3_CACHE SearchCR3Node(HANDLE ProcessId) {

	ExAcquireFastMutex(&cr3_mutex);
	if (!CR3_STARTNODE || ProcessId == 0) {
		ExReleaseFastMutex(&cr3_mutex);
		return NULL;
	}

	PCR3_CACHE current = CR3_STARTNODE;
	while (current) {
		if (current->ProcessId == ProcessId) {
			ExReleaseFastMutex(&cr3_mutex);
			return current;
		}
		current = current->NextNode;
	}
	ExReleaseFastMutex(&cr3_mutex);
	return NULL;
}

// --

NTSTATUS AttachProcessStack(
	_In_ PEPROCESS Process,
	_Inout_ PKAPC_STATE ApcState
) {
	if (!Process || !ApcState) {
		return STATUS_INVALID_PARAMETER;
	}

	UINT64 CR3 = Get_CR3(Process);

	if (CR3) {
		KeStackAttachProcess(Process, ApcState);
		__writecr3(CR3);
		return STATUS_SUCCESS; // CR3 found for the process
	}
	else {
		KeStackAttachProcess(Process, ApcState);
		return STATUS_UNSUCCESSFUL; // CR3 not found for the process
	}

}

VOID DetachProcessStack(
	//_In_ BOOLEAN is_success_cr3,
	_In_ PKAPC_STATE ApcState
) {

	KeUnstackDetachProcess(ApcState);
}