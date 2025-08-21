#include "API.h"

PCREATE_PROCESS_NOTIFY_ROUTINE_EX_by_gamehack PsSetCreateProcessNotifyRoutineEx_ = NULL;
PsSetCreateThreadNotifyRoutine_by_gamehack PsSetCreateThreadNotifyRoutine_ = NULL;

PUCHAR get_kernel_api_address(PWCH api_name) {
	UNICODE_STRING tmp_api_name = { 0, };
	RtlInitUnicodeString(&tmp_api_name, api_name);

	return (PUCHAR)MmGetSystemRoutineAddress(&tmp_api_name);
}

NTSTATUS Load_KernelAPIs() {

	PsSetCreateProcessNotifyRoutineEx_ = (PCREATE_PROCESS_NOTIFY_ROUTINE_EX_by_gamehack)get_kernel_api_address(L"PsSetCreateProcessNotifyRoutineEx");
	if (!PsSetCreateProcessNotifyRoutineEx_)
		return STATUS_UNSUCCESSFUL;

	PsSetCreateThreadNotifyRoutine_ = (PsSetCreateThreadNotifyRoutine_by_gamehack)get_kernel_api_address(L"PsSetCreateThreadNotifyRoutine");
	if (!PsSetCreateThreadNotifyRoutine_)
		return STATUS_UNSUCCESSFUL;


	return STATUS_SUCCESS;
}