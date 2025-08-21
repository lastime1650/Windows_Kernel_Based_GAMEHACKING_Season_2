#pragma warning(disable:4100)

#include "NotifyRoutines.h"
#include "ProcessMonitor.h"

VOID ProcessCreateRoutineEx_HANDLER(
    _Inout_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo
) {
    PrintALLProcessMon();
    if (CreateInfo) {
        // Process Create
        Save_To_ProcessMonNode(Process);
    }
    else {
        // Process Remove
        Remove_One_ProcessNode(Process);
    }
}


#include "API.h"
NTSTATUS Load_NotifyRoutines() {
    if( !NT_SUCCESS( PsSetCreateProcessNotifyRoutineEx_(ProcessCreateRoutineEx_HANDLER, FALSE)) )
        return STATUS_UNSUCCESSFUL;

    return STATUS_SUCCESS;
}