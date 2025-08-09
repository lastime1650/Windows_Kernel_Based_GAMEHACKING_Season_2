#include "NamedPipe.h"

#include <stdio.h>


DWORD WINAPI loop_receive_by_client(HANDLE PIPE_HANDLE ); // 항상 수신상태 ( 생성자 부분에서 가능

/*
NamedPipeManager::NamedPipeManager() {
	CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)&Do_PIPE, NULL, 0, NULL);
}
*/

DWORD WINAPI Do_PIPE(PVOID empty) {

	UNREFERENCED_PARAMETER(empty);

	while (1) {
		HANDLE Pipe_HANDLE = CreateNamedPipe(
			PIPE_NAME,
			PIPE_ACCESS_INBOUND,
			PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
			PIPE_UNLIMITED_INSTANCES,
			MAXIMUM_BUFFER_SIZE,
			MAXIMUM_BUFFER_SIZE,
			0,
			NULL
		);
		printf("[NamedPipe] 연결 대기중 \n");

		if (!ConnectNamedPipe(Pipe_HANDLE, NULL)) {
			CloseHandle(Pipe_HANDLE);
			continue;
		}

		printf("[NamedPipe] 연결 됨 \n");

		CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)&loop_receive_by_client, (LPVOID)Pipe_HANDLE, 0, NULL);
	}
	
	
	return 0;
}


void printContext(const CONTEXT* ctx);
DWORD WINAPI loop_receive_by_client(HANDLE PIPE_HANDLE)
{

	DWORD bytesRead;
	VEH_information buffer;

	while (ReadFile(PIPE_HANDLE, &buffer, sizeof(buffer), &bytesRead, NULL) && bytesRead > 0) {

		printf("\n===========================================\n");

		printf("[NamedPipe] PID: %d, Size: %lu\n", (DWORD)buffer.processId, bytesRead);

		printf("[NamedPipe] 발생한 CODE영역: %p \n", (PVOID)buffer.context.Rip);


		if (buffer.context.Dr6 & 0x1) {
			// dr0에서 BP 발생
			printf("[NamedPipe]  dr0에서 BP 발생 \n");
		}
		if (buffer.context.Dr6 & 0x2) {
			// dr1에서 BP 발생
			printf("[NamedPipe]  dr1에서 BP 발생 \n");
		}
		if (buffer.context.Dr6 & 0x4) {
			// dr2에서 BP 발생
			printf("[NamedPipe]  dr2에서 BP 발생 \n");
		}
		if (buffer.context.Dr6 & 0x8) {
			// dr3에서 BP 발생
			printf("[NamedPipe]  dr3에서 BP 발생 \n");
		}

        printContext(&buffer.context);

		printf("===========================================\n");

	}

	DisconnectNamedPipe(PIPE_HANDLE);
	CloseHandle(PIPE_HANDLE);
	return 0;
}


void printContext(const CONTEXT* ctx) {
    printf("P1Home: 0x%llx\n", ctx->P1Home);
    printf("P2Home: 0x%llx\n", ctx->P2Home);
    printf("P3Home: 0x%llx\n", ctx->P3Home);
    printf("P4Home: 0x%llx\n", ctx->P4Home);
    printf("P5Home: 0x%llx\n", ctx->P5Home);
    printf("P6Home: 0x%llx\n", ctx->P6Home);

    printf("ContextFlags: 0x%x\n", ctx->ContextFlags);
    printf("MxCsr: 0x%x\n", ctx->MxCsr);

    printf("SegCs: 0x%hx\n", ctx->SegCs);
    printf("SegDs: 0x%hx\n", ctx->SegDs);
    printf("SegEs: 0x%hx\n", ctx->SegEs);
    printf("SegFs: 0x%hx\n", ctx->SegFs);
    printf("SegGs: 0x%hx\n", ctx->SegGs);
    printf("SegSs: 0x%hx\n", ctx->SegSs);
    printf("EFlags: 0x%x\n", ctx->EFlags);

    printf("Dr0: 0x%llx\n", ctx->Dr0);
    printf("Dr1: 0x%llx\n", ctx->Dr1);
    printf("Dr2: 0x%llx\n", ctx->Dr2);
    printf("Dr3: 0x%llx\n", ctx->Dr3);
    printf("Dr6: 0x%llx\n", ctx->Dr6);
    printf("Dr7: 0x%llx\n", ctx->Dr7);

    printf("Rax: 0x%llx\n", ctx->Rax);
    printf("Rcx: 0x%llx\n", ctx->Rcx);
    printf("Rdx: 0x%llx\n", ctx->Rdx);
    printf("Rbx: 0x%llx\n", ctx->Rbx);
    printf("Rsp: 0x%llx\n", ctx->Rsp);
    printf("Rbp: 0x%llx\n", ctx->Rbp);
    printf("Rsi: 0x%llx\n", ctx->Rsi);
    printf("Rdi: 0x%llx\n", ctx->Rdi);
    printf("R8:  0x%llx\n", ctx->R8);
    printf("R9:  0x%llx\n", ctx->R9);
    printf("R10: 0x%llx\n", ctx->R10);
    printf("R11: 0x%llx\n", ctx->R11);
    printf("R12: 0x%llx\n", ctx->R12);
    printf("R13: 0x%llx\n", ctx->R13);
    printf("R14: 0x%llx\n", ctx->R14);
    printf("R15: 0x%llx\n", ctx->R15);

    printf("Rip: 0x%llx\n", ctx->Rip);

    printf("Xmm0:  0x%llx 0x%llx\n", ctx->Xmm0.Low, ctx->Xmm0.High);
    printf("Xmm1:  0x%llx 0x%llx\n", ctx->Xmm1.Low, ctx->Xmm1.High);
    printf("Xmm2:  0x%llx 0x%llx\n", ctx->Xmm2.Low, ctx->Xmm2.High);
    printf("Xmm3:  0x%llx 0x%llx\n", ctx->Xmm3.Low, ctx->Xmm3.High);
    printf("Xmm4:  0x%llx 0x%llx\n", ctx->Xmm4.Low, ctx->Xmm4.High);
    printf("Xmm5:  0x%llx 0x%llx\n", ctx->Xmm5.Low, ctx->Xmm5.High);
    printf("Xmm6:  0x%llx 0x%llx\n", ctx->Xmm6.Low, ctx->Xmm6.High);
    printf("Xmm7:  0x%llx 0x%llx\n", ctx->Xmm7.Low, ctx->Xmm7.High);
    printf("Xmm8:  0x%llx 0x%llx\n", ctx->Xmm8.Low, ctx->Xmm8.High);
    printf("Xmm9:  0x%llx 0x%llx\n", ctx->Xmm9.Low, ctx->Xmm9.High);
    printf("Xmm10: 0x%llx 0x%llx\n", ctx->Xmm10.Low, ctx->Xmm10.High);
    printf("Xmm11: 0x%llx 0x%llx\n", ctx->Xmm11.Low, ctx->Xmm11.High);
    printf("Xmm12: 0x%llx 0x%llx\n", ctx->Xmm12.Low, ctx->Xmm12.High);
    printf("Xmm13: 0x%llx 0x%llx\n", ctx->Xmm13.Low, ctx->Xmm13.High);
    printf("Xmm14: 0x%llx 0x%llx\n", ctx->Xmm14.Low, ctx->Xmm14.High);
    printf("Xmm15: 0x%llx 0x%llx\n", ctx->Xmm15.Low, ctx->Xmm15.High);

    for (int i = 0; i < 26; i++) {
        printf("VectorRegister[%d]: 0x%llx 0x%llx\n", i, ctx->VectorRegister[i].Low, ctx->VectorRegister[i].High);
    }

    printf("VectorControl: 0x%llx\n", ctx->VectorControl);

    printf("DebugControl: 0x%llx\n", ctx->DebugControl);
    printf("LastBranchToRip: 0x%llx\n", ctx->LastBranchToRip);
    printf("LastBranchFromRip: 0x%llx\n", ctx->LastBranchFromRip);
    printf("LastExceptionToRip: 0x%llx\n", ctx->LastExceptionToRip);
    printf("LastExceptionFromRip: 0x%llx\n", ctx->LastExceptionFromRip);
}
