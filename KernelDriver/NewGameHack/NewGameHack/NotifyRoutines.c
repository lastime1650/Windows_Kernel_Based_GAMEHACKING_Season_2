#pragma warning(disable:4100)

#include "NotifyRoutines.h"
#include "ProcessMonitor.h"

#include "CR3_Cache.h"
#include "UserProcess_Helper.h"

VOID ProcessCreateRoutineEx_HANDLER(
    _Inout_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo
) {
    //PrintALLProcessMon();
    if (CreateInfo) {

		//SaveCR3(Process); // Save CR3 to cache


        // Process Create
        Save_To_ProcessMonNode(Process); //-> Not using now
        Get_CR3_by_BruteForce(Process);
    }
    else {
		//RemoveCR3(Process); // Remove CR3 from cache

        // Process Remove
        Remove_One_ProcessNode(Process); //-> Not using now
    }
}


#include "API.h"
NTSTATUS Load_NotifyRoutines() {

    Init_CR3();  // CR3 °ü¸® 

    if( !NT_SUCCESS( PsSetCreateProcessNotifyRoutineEx_(ProcessCreateRoutineEx_HANDLER, FALSE)) )
        return STATUS_UNSUCCESSFUL;

    return STATUS_SUCCESS;
}