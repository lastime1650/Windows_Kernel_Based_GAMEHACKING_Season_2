#pragma warning(disable:4996)
#include "HardwareBP.h"

#include "API.h"
#include "Process.h"

#include "GetProcessAPIAddress.h"

NTSTATUS Set_Hardware_BreakPoint(
	HANDLE ProcessId,
	PUCHAR TargetAddress,
	BOOLEAN isRemove
) {
	if (!TargetAddress)
		return STATUS_INVALID_PARAMETER;


	NTSTATUS status = STATUS_UNSUCCESSFUL;

	/*
		[�߰�]
		-> �����ϰ� �ϵ���� �극��ũ����Ʈ �ɱ� ���� �������API�� Suspend/Resume Thread API ȣ���� �� �ֵ��� �Ѵ�.
	*/
	
	Got_UserThread_APIs TargetProcess_APIs = { 0, };
	status = Get_ALL_APIS(
		ProcessId,
		&TargetProcess_APIs
	);
	if (!NT_SUCCESS(status))
		return status;
	//HANDLE returned_userthread_handle = NULL;

	PProcess_info TargetProcess = NULL;
	status = GetProcessInfoByProcessId(ProcessId, &TargetProcess);
	if (!NT_SUCCESS(status))
		goto EXIT1;

	ULONG32 bufferSize = 0; // Initial buffer size
	PUCHAR buffer = NULL;
	while (ZwQuerySystemInformation(SystemProcessInformation, buffer, bufferSize, &(ULONG)bufferSize) == STATUS_INFO_LENGTH_MISMATCH) {
		if (buffer == NULL) {
			buffer = ExAllocatePoolWithTag(NonPagedPool, bufferSize, 'QRPS'); // QueRyProceSs
			if (buffer == NULL) {
				DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, " Failed Memory Allocate \n");
				status = STATUS_INSUFFICIENT_RESOURCES;
				goto EXIT1;
			}
		}
	}
	PSYSTEM_PROCESS_INFORMATION processInfo = (PSYSTEM_PROCESS_INFORMATION)buffer;
	while (processInfo) {
		if (processInfo->UniqueProcessId == ProcessId) {
			PSYSTEM_THREAD_INFORMATION threadInfo = processInfo->Threads;
			for (ULONG i = 0; i < processInfo->NumberOfThreads; i++) {

				HANDLE ThreadID = threadInfo[i].ClientId.UniqueThread; // get thread id

				// Get PETHREAD
				PETHREAD Thread = NULL;
				if (PsLookupThreadByThreadId(ThreadID, &Thread) != STATUS_SUCCESS) {
					DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, " ������ ��ü ��� ���� \n");
					threadInfo++;
					continue;
				}

				// Get Thread Handle
				HANDLE ThreadHandle = NULL;
				status = ObOpenObjectByPointer(
					Thread,
					OBJ_KERNEL_HANDLE,
					NULL,
					THREAD_ALL_ACCESS,
					*PsThreadType,
					KernelMode,
					&ThreadHandle
				);
				if (!NT_SUCCESS(status)) {
					DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, " ������ �ڵ� ��� ���� \n");
					ObDereferenceObject(Thread); // Dereference PETHREAD
					threadInfo++;
					continue;
				}

				KAPC_STATE APC_STATE = { 0, };
				KeStackAttachProcess(TargetProcess->ProcessObject, &APC_STATE); // Attach to the target process context

				/*
				HANDLE pUserThreadHandle = NULL;
				status = ObOpenObjectByPointer(
					Thread,
					0,
					NULL,
					THREAD_ALL_ACCESS,
					*PsThreadType,
					UserMode,
					&pUserThreadHandle
				);
				if (!NT_SUCCESS(status)) {
					KeUnstackDetachProcess(&APC_STATE);

					DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, " ������ �ڵ� ��� ���� \n");
					ObDereferenceObject(Thread); // Dereference PETHREAD
					threadInfo++;
					continue;
				}
				*/
				/*
				
					Suspend Process/Thread
				
				*/
				
				/*
				Call_2_User_Thread(
					TargetProcess->ProcessHandle,
					TargetProcess_APIs.SuspendThread_Address,
					(PVOID)pUserThreadHandle, // �ּҰ� �ƴ�, HANDLE �״�� �� �����ؾ��Ѵ�.
					&returned_userthread_handle
				);*/
				status = PsSuspendProcess(TargetProcess->ProcessObject);
				if (!NT_SUCCESS(status)) {
					KeUnstackDetachProcess(&APC_STATE);

					DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, " PsSuspendProcess ���� \n");
					ObDereferenceObject(Thread); // Dereference PETHREAD
					threadInfo++;
					continue;
				}

				



				/*

					Get Thread Context ( current )

				*/
				PCONTEXT context_USERMODE = NULL;

				SIZE_T contextSize = sizeof(CONTEXT);
				ZwAllocateVirtualMemory(
					TargetProcess->ProcessHandle,
					&context_USERMODE,
					0,
					&contextSize,
					MEM_COMMIT,
					PAGE_READWRITE
				);
				memset(context_USERMODE, 0, contextSize); // Initialize context to zero
				context_USERMODE->ContextFlags = CONTEXT_ALL;

				status = PsGetContextThread(Thread, context_USERMODE, UserMode);
				if (!NT_SUCCESS(status)) {

					PsResumeProcess(TargetProcess->ProcessObject);

					KeUnstackDetachProcess(&APC_STATE); // Detach from the target process context

					DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, " ������ ���ؽ�Ʈ ��� ���� \n");
					ObCloseHandle(ThreadHandle, KernelMode);
					ObDereferenceObject(Thread); // Dereference PETHREAD

					/*
					status = Call_2_User_Thread(
						TargetProcess->ProcessHandle,
						TargetProcess_APIs.ResumeThread_Address,
						(PVOID)pUserThreadHandle, // �ּҰ� �ƴ�, HANDLE �״�� �� �����ؾ��Ѵ�.
						&returned_userthread_handle
					);*/

					threadInfo++;
					continue;
				}





				if (!TargetProcess->is64bit) {
					// 32 bit
					// Set Hardware Breakpoint
					if (isRemove) {
						context_USERMODE->Dr0 = 0;
						context_USERMODE->Dr1 = 0;
						context_USERMODE->Dr2 = 0;
						context_USERMODE->Dr3 = 0;
						context_USERMODE->Dr6 = 0;
						context_USERMODE->Dr7 = 0;
					}
					else {

						context_USERMODE->Dr0 = 0;
						context_USERMODE->Dr1 = 0;
						context_USERMODE->Dr2 = 0;
						context_USERMODE->Dr3 = 0;
						context_USERMODE->Dr6 = 0;
						context_USERMODE->Dr7 = 0;


						context_USERMODE->Dr0 = (ULONG64)TargetAddress; // Example address, replace with actual target address
						context_USERMODE->Dr7 |= (1 << 0);
						context_USERMODE->Dr7 |= (3 << (16 + (0 * 4)));
						context_USERMODE->Dr7 |= (3 << (18 + (0 * 4)));

						/* Dr1: Execute( 00 ) - 4����Ʈ���� (�������� ũ�����)*/
						context_USERMODE->Dr1 = (ULONG64)TargetAddress;
						context_USERMODE->Dr7 |= (1 << 2);
						context_USERMODE->Dr7 |= (0 << (16 + 1 * 4)); // Execute
						context_USERMODE->Dr7 |= (3 << (18 + 1 * 4)); // ũ��(4����Ʈ) 
					}
					
				}
				else {
					// 64bit
					
					if (isRemove) {
						context_USERMODE->Dr0 = 0;
						context_USERMODE->Dr1 = 0;
						context_USERMODE->Dr2 = 0;
						context_USERMODE->Dr3 = 0;

						// Dr7���� ��� �극��ũ����Ʈ ���� ��Ʈ�� Ŭ����
						context_USERMODE->Dr6 = 0;
						context_USERMODE->Dr7 = 0;
					}
					else {

						context_USERMODE->Dr0 = 0;
						context_USERMODE->Dr1 = 0;
						context_USERMODE->Dr2 = 0;
						context_USERMODE->Dr3 = 0;
						context_USERMODE->Dr6 = 0;
						context_USERMODE->Dr7 = 0;

						/* Dr2: Read/Write( 11 ) - 8����Ʈ���� */
						context_USERMODE->Dr2 = (ULONG64)TargetAddress;
						context_USERMODE->Dr7 |= (1 << 4);
						context_USERMODE->Dr7 |= (3 << (16 + 2 * 4)); // ReadWrite
						context_USERMODE->Dr7 |= (2 << (18 + 2 * 4)); // ũ�� 8����Ʈ


						/* Dr3: Execute( 00 ) - 8����Ʈ���� */
						context_USERMODE->Dr3 = (ULONG64)TargetAddress;
						context_USERMODE->Dr7 |= (1 << 6);
						context_USERMODE->Dr7 |= (0 << (16 + 3 * 4));  // Execute
						context_USERMODE->Dr7 |= (2 << (18 + 3 * 4));  // ũ�� 8����Ʈ
					}
					
				}

				PsSetContextThread(Thread, context_USERMODE, UserMode);

				PsResumeProcess(TargetProcess->ProcessObject);


				KeUnstackDetachProcess(&APC_STATE); // Detach from the target process context

				/*
				
					Resume User Thread
				
				*/

				/*
				status = Call_2_User_Thread(
					TargetProcess->ProcessHandle,
					TargetProcess_APIs.ResumeThread_Address,
					(PVOID)pUserThreadHandle, // �ּҰ� �ƴ�, HANDLE �״�� �� �����ؾ��Ѵ�.
					&returned_userthread_handle
				);*/
				
				ObDereferenceObject(Thread); // Dereference PETHREAD
				threadInfo++;


				DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, " ���ؽ�Ʈ ���� \n");
			}

			break;
		}
		processInfo = (PSYSTEM_PROCESS_INFORMATION)((PUCHAR)processInfo + processInfo->NextEntryOffset);
	}

	goto EXIT2;

EXIT2:
	if (buffer)
		ExFreePoolWithTag(buffer, 'QRPS');
EXIT1:
	if (TargetProcess)
		ReleaseProcessInfo(TargetProcess);
	return status;
}