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

			// 중요: 무한 루프 방지를 위해 Resume Flag를 설정합니다.
			//ctx->EFlags |= EFLAGS_RF_BIT;

			// 중요: Trap Flag를 강제로 끈다. ( 안티치트가 Trap 을 걸어두는 경우를 대비하여 꺼야함 ) 
			//ctx->EFlags &= ~EFLAGS_TF_BIT;
			return EXCEPTION_CONTINUE_EXECUTION; // SINGLE_STEP 등 자신이 설정한 HWBP에 대한 처리면, CONTINUE EXECUTION
		}
	}
	
	return EXCEPTION_CONTINUE_SEARCH; // SINGLE_STEP 등 자신이 설정한 HWBP에 대한 처리가 아니면 ..SEARCH로 반환
}			