#ifndef CR3_CACHE_H
#define CR3_CACHE_H

#include <ntifs.h>

#define CR3_CACHE_TAG 'CR3T'

#include <intrin.h>
#define CR3_64BIT_ADDRESS_OFFSET 0x28

typedef struct CR3_CACHE_ {

	HANDLE ProcessId;          // Process ID
	ULONG64 CR3;         // CR3 value (Page Directory Base)



	struct CR3_CACHE_* NextNode;

} CR3_CACHE, *PCR3_CACHE;

extern PCR3_CACHE CR3_STARTNODE;
extern PCR3_CACHE CR3_CURRENTNODE;

extern FAST_MUTEX cr3_mutex;

VOID Init_CR3();

BOOLEAN SaveCR3(_In_ PEPROCESS Process);
VOID RemoveCR3(_In_ PEPROCESS Process);



NTSTATUS AttachProcessStack(
	_In_ PEPROCESS Process,

	_Inout_ PKAPC_STATE ApcState
);

VOID DetachProcessStack(
	PKAPC_STATE ApcState
);

#endif