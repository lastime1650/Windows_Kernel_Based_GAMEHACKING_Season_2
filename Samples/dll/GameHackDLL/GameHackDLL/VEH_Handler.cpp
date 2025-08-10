#include "pch.h"
#include "VEH_handler.h"

#include <stdio.h>

HANDLE myProcessId = (HANDLE)GetCurrentProcessId();

LONG CALLBACK ExceptionVectorHandler(PEXCEPTION_POINTERS ExceptionInfo);

BOOLEAN VEH_Handler()
{
	return \
		(
			AddVectoredExceptionHandler(1, ExceptionVectorHandler) != NULL
			);
}


#include "NamedPipe.h"

#define EFLAGS_TF_BIT 0x00000100 //  (1 << 8)
#define EFLAGS_RF_BIT 0x10000  // 1 << 16
// Real VEH Handler
LONG CALLBACK ExceptionVectorHandler(PEXCEPTION_POINTERS ExceptionInfo)
{

	CONTEXT* ctx = ExceptionInfo->ContextRecord;
	
	if (ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP) {

		
		if (ctx->Dr6 & 0xF) {
			VEH_information log = { 0, };
			log.processId = myProcessId;
			log.ExceptionCode = ExceptionInfo->ExceptionRecord->ExceptionCode;
			log.context = *ExceptionInfo->ContextRecord;


			SendData(
				&log,
				sizeof(VEH_information)
			);

			// �߿�: ���� ���� ������ ���� Resume Flag�� �����մϴ�.
			//ctx->EFlags |= EFLAGS_RF_BIT;

			// �߿�: Trap Flag�� ������ ����. ( ��ƼġƮ�� Trap �� �ɾ�δ� ��츦 ����Ͽ� ������ ) 
			//ctx->EFlags &= ~EFLAGS_TF_BIT;
			return EXCEPTION_CONTINUE_EXECUTION; // SINGLE_STEP �� �ڽ��� ������ HWBP�� ���� ó����, CONTINUE EXECUTION
		}
	}
	
	return EXCEPTION_CONTINUE_SEARCH; // SINGLE_STEP �� �ڽ��� ������ HWBP�� ���� ó���� �ƴϸ� ..SEARCH�� ��ȯ
}			