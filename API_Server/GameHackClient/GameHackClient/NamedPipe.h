#ifndef NAMEDPIPE_H
#define NAMEDPIPE_H

#include <Windows.h>



typedef struct VEH_information {

	HANDLE processId;
	DWORD ExceptionCode;

	CONTEXT context;

}VEH_information, * PVEH_information;


#define PIPE_NAME L"\\\\.\\pipe\\VEH_PIPE"
#define MAXIMUM_BUFFER_SIZE sizeof(VEH_information)

DWORD WINAPI Do_PIPE(PVOID empty);

#endif