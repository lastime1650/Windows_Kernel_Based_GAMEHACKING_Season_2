#ifndef API_FUNC_POINTER_H
#define API_FUNC_POINTER_H

#include <ntifs.h>


typedef NTSTATUS(*PCREATE_PROCESS_NOTIFY_ROUTINE_EX_by_gamehack)(
    PCREATE_PROCESS_NOTIFY_ROUTINE_EX NotifyRoutine,
    BOOLEAN Remove
    );

extern PCREATE_PROCESS_NOTIFY_ROUTINE_EX_by_gamehack PsSetCreateProcessNotifyRoutineEx_;

typedef NTSTATUS(*PsSetCreateThreadNotifyRoutine_by_gamehack)(
    PCREATE_THREAD_NOTIFY_ROUTINE NotifyRoutine
    );

extern PsSetCreateThreadNotifyRoutine_by_gamehack PsSetCreateThreadNotifyRoutine_;

#endif