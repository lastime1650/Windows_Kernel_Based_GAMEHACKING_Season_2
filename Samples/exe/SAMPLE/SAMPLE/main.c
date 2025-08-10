#include <Windows.h>
#include <stdio.h>

HANDLE IOCTL_HANDLE = NULL;

// Kernel 32 �ּҿ� LoadLibraryA () �ּҸ� ���

#define BUFFER_SIZE sizeof(CONTEXT) // context �״�� �ޱ�

VOID Pipe_Receive_Thread(PVOID paramter);


#define SYMBOLIC_NAME L"\\??\\NewGameHack"

int main() {

	// IOCTL ����
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
		printf("IOCTL �ڵ� ��ȿ���� ����\n");
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


	printf("�ڽ��� ThreadID: %d\n", GetCurrentThreadId());
	HANDLE hCurrentThread = GetCurrentThread(); // Ư�� �ڵ�
	HANDLE hDupThread = NULL;

	BOOL success = DuplicateHandle(
		GetCurrentProcess(),   // ���� ���μ��� (���� �ڵ� ������)
		hCurrentThread,        // ������ �ڵ�
		GetCurrentProcess(),   // ��� ���μ��� (���纻 �ڵ� ������)
		&hDupThread,           // ���纻 �ڵ� ��ȯ
		THREAD_ALL_ACCESS,     // ����
		FALSE,                 // ��� ����
		0
	);
	printf("�Ϲ�-�������ڵ� %d\n", hCurrentThread);
	printf("�ܺ� ���� ������ ThreadHandle %p\n", hDupThread);

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

		// � ���� �������� �÷��� ����
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
	
	printf("NamedPIPE Ŭ���̾�Ʈ �����..\n");
	ConnectNamedPipe(hPipe, NULL); // Ŭ���̾�Ʈ ���
	printf("NamedPIPE Ŭ���̾�Ʈ �����..\n");

	DWORD bytesRead = 0;
	char BUFFER[BUFFER_SIZE] = { 0, };
	while ( ReadFile(hPipe, BUFFER, BUFFER_SIZE, &bytesRead, NULL) ) {
		printf("PIPE ������ ���ŵ� ũ��: %d\n", bytesRead);

		PCONTEXT context = (PCONTEXT)&BUFFER;

		printf("[TEST] context - %p\n", context->Dr6);

	}

}