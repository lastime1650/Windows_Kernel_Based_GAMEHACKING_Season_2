#ifndef PIPE_CONNECT_H
#define PIPE_CONNECT_H

#include <Windows.h>

typedef struct VEH_information {

	HANDLE processId;
	DWORD ExceptionCode;

	CONTEXT context;

}VEH_information, * PVEH_information;

#define PIPE_NAME L"\\\\.\\pipe\\VEH_PIPE"
#define MAXIMUM_BUFFER_SIZE sizeof(VEH_information)

extern HANDLE PIPE_HANDLE;

BOOLEAN ConnectPIPE_Server();

BOOLEAN SendData(const void* data, DWORD dataSize);

#endif