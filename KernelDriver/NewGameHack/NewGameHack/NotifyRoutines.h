#ifndef NotifyRoutines_H
#define NotifyRoutines_H

#include <ntifs.h>



VOID ProcessCreateRoutineEx_HANDLER(
    _Inout_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo
);





VOID ThreadCreateRoutine_HANDLER(
    _In_ HANDLE ProcessId,
    _In_ HANDLE ThreadId,
    _In_ BOOLEAN Create
);

NTSTATUS Load_NotifyRoutines();

#endif 