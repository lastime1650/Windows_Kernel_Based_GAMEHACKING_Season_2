#ifndef PointerScan_H
#define PointerScan_H

#include "Scan.h"

// --- Pool Tags ---
#define POINTER_MAP_TAG     'mPtP'
#define POINTER_PATH_TAG    'pPtP'
#define TEMP_BUFFER_TAG     'bPtP'
#define THREAD_OBJECTS_TAG  'oPtP'
#define SCAN_CONTEXT_TAG    'cPtP'
#define OFFSETS_ARRAY_TAG   'aPtP'





#define MEM_IMAGE                   0x01000000  
NTSTATUS PointerScanning(
    _In_ HANDLE RequesterPID,
    _In_ HANDLE TargetPID,
    _In_ PVOID TargetAddress,
    _In_ ULONG32 MaxDepth,
    _In_ UINT32 NumThreads,
    _In_ LONG_PTR MaxBaseOffset,
    _In_ LONG_PTR MaxChainOffset,
    _In_ UINT32 MinPointersInPeek,
    _Out_ PPointerScannedNode* output
);


#endif