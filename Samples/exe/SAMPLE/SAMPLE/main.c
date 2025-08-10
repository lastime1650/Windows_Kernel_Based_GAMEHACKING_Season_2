#include <Windows.h>
#include <stdio.h>

HANDLE IOCTL_HANDLE = NULL;

// Kernel 32 주소와 LoadLibraryA () 주소를 출력

#define BUFFER_SIZE sizeof(CONTEXT) // context 그대로 받기

VOID Pipe_Receive_Thread(PVOID paramter);


#define SYMBOLIC_NAME L"\\??\\NewGameHack"

int main() {

	// IOCTL 접근
	/*IOCTL_HANDLE = CreateFileW(
		SYMBOLIC_NAME,
		GENERIC_READ | GENERIC_WRITE,
		0,
		NULL,
		OPEN_EXISTING,
		0,
		NULL
	);
	if (IOCTL_HANDLE == INVALID_HANDLE_VALUE) {
		printf("IOCTL 핸들 유효하지 않음\n");
		system("pause");
		return -1;
	}*/


	///////////////////////////////////

	printf("Process ID: %lu\n",
		GetCurrentProcessId()
	);

	HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
	if (hKernel32 == NULL) {
		printf("Failed to get handle for kernel32.dll\n");
		return 1;
	}

	FARPROC pLoadLibraryA = GetProcAddress(hKernel32, "LoadLibraryA");
	if (pLoadLibraryA == NULL) {
		printf("Failed to get address for LoadLibraryA\n");
		return 1;
	}

	printf("Kernel32.dll Address: %p\n", hKernel32);
	printf("LoadLibraryA Address: %p\n\n", pLoadLibraryA);


	printf("자신의 ThreadID: %d\n", GetCurrentThreadId());
	HANDLE hCurrentThread = GetCurrentThread(); // 특수 핸들
	HANDLE hDupThread = NULL;

	BOOL success = DuplicateHandle(
		GetCurrentProcess(),   // 현재 프로세스 (원본 핸들 소유자)
		hCurrentThread,        // 복사할 핸들
		GetCurrentProcess(),   // 대상 프로세스 (복사본 핸들 소유자)
		&hDupThread,           // 복사본 핸들 반환
		THREAD_ALL_ACCESS,     // 권한
		FALSE,                 // 상속 여부
		0
	);
	printf("일반-스레드핸들 %d\n", hCurrentThread);
	printf("외부 참조 가능한 ThreadHandle %p\n", hDupThread);

	printf("SuspendThread Address: %p\n", GetProcAddress(hKernel32, "SuspendThread"));
	printf("ResumeThread Address: %p\n", GetProcAddress(hKernel32, "ResumeThread"));
	
	printf("\n\n");
	////////////////////////////////////////////////////////////////////////////
	/*
	CreateThread(
		NULL,
		0,
		(LPTHREAD_START_ROUTINE)Pipe_Receive_Thread,
		NULL,
		0,
		NULL
	);
	*/

	////////////////////////////////////////////////////////////////////////////
	ULONG32 value1 = 0;
	FLOAT value2 = 0.0f;
	DOUBLE value3 = 0.0;

	while (value1 < 100) {
		
		value1 += 1;
		value2 += 0.1f;
		value3 += 0.01;

		printf("Value1(%p): %lu, Value2(%p): %.2f, Value3(%p): %.2f\n",
			&value1,
			value1,

			&value2,
			value2,
			
			& value3,
			value3
		);

		HANDLE hThread = GetCurrentThread();
		CONTEXT ctx;

		// 어떤 값을 가져올지 플래그 설정
		ctx.ContextFlags = CONTEXT_FULL;

		if (GetThreadContext(hThread, &ctx)) {
			printf("DR0 = 0x%llx\n", ctx.Dr0);
			printf("DR1 = 0x%llx\n", ctx.Dr1);
			printf("DR2 = 0x%llx\n", ctx.Dr2);
			printf("DR3 = 0x%llx\n", ctx.Dr3);
			printf("DR6 = 0x%llx\n", ctx.Dr6);
			printf("DR7 = 0x%llx\n", ctx.Dr7);
		}
		else {
			printf("GetThreadContext failed. Error: %lu\n", GetLastError());
		}



		system("pause");
		
	}
	return 0;
}


VOID Pipe_Receive_Thread(PHANDLE PIPE_HANDLE) {


	HANDLE hPipe = CreateNamedPipe(
		L"\\\\.\\pipe\\ContextPipe",
		PIPE_ACCESS_INBOUND,
		PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
		1,
		BUFFER_SIZE,
		BUFFER_SIZE,
		0,
		NULL
	);
	
	printf("NamedPIPE 클라이언트 대기중..\n");
	ConnectNamedPipe(hPipe, NULL); // 클라이언트 대기
	printf("NamedPIPE 클라이언트 연결된..\n");

	DWORD bytesRead = 0;
	char BUFFER[BUFFER_SIZE] = { 0, };
	while ( ReadFile(hPipe, BUFFER, BUFFER_SIZE, &bytesRead, NULL) ) {
		printf("PIPE 데이터 수신됨 크기: %d\n", bytesRead);

		PCONTEXT context = (PCONTEXT)&BUFFER;

		printf("[TEST] context - %p\n", context->Dr6);

	}

}