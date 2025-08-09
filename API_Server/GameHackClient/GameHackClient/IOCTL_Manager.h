#ifndef IOCTL_MANAGER_H
#define IOCTL_MANAGER_H

#include <Windows.h>
#include "IOCTL_Share.h"
#include "NamedPipe.h"

#include <functional>
#include <string>

#include <rapidjson/document.h>



using SendCallback = std::function<void(const std::string&)>; // WebSocket, 전송 콜백

class IOCTL_Manager {
public:
	IOCTL_Manager();
	~IOCTL_Manager(); // 클래스 해제

	BOOLEAN IsConnected();

	

	// Scanning
	std::string NewScanning(rapidjson::Document& JSON);
	std::string AddressScanning(rapidjson::Document& JSON);

	// Dump
	std::string MemDumping(rapidjson::Document& JSON);
	
	// DLL Injection
	std::string DLL_Injection(rapidjson::Document& JSON);

	// Mem Write
	std::string MemWriting(rapidjson::Document& JSON);

	// HardWare BreakPoint
	std::string Set_HW_BP(rapidjson::Document& JSON); // it depends that NamedPipe ! 
	
	std::string MemAllScanning(rapidjson::Document& JSON);


private:
	DWORD MyPID = 0;

	HANDLE IOCTL_Handle = NULL;
	BOOLEAN IsConnect = FALSE;

	/*
	
	*/

	PScanNode newscan(HANDLE Target_ProcessId, PUCHAR value_data, SIZE_T value_size);// 반환값 -> 연결리스트 시작 노드 주소 또는 NULL(실패)
	PAddressScanned addressscan(HANDLE Target_ProcessId, PUCHAR TargetAddress, PUCHAR value_data, SIZE_T value_size); // 반환값 -> 요청한 <TargetAddress> 값을 그대로 받은 경우, 여전히 일치하다는 의미(성공). 또는 NULL(실패)
	PMemDumpOutput memdump(HANDLE Target_ProcessId, PUCHAR TargetAddress, SIZE_T dump_size); // 반환값 -> 요청한 <TargetAddress> 값을 그대로 받은 경우, 여전히 일치하다는 의미(성공). 또는 NULL(실패)
	NTSTATUS dll_injection(HANDLE Target_ProcessId, const char* DLL_NAME, PUCHAR DLL_BUFFER, SIZE_T DLL_BUFFER_SIZE);
	NTSTATUS set_HardwareBP(HANDLE Target_ProcessId, PUCHAR TargetAddress, BOOLEAN is_remove);
	PUCHAR memwrite(HANDLE Target_ProcessId, PUCHAR TargetAddress, PUCHAR value_data, SIZE_T value_size, BOOLEAN is_Protect_Change_Enable);
	PAllScannedNode allscan(HANDLE Target_ProcessId, SIZE_T value_size);

	BOOL call_to_kernel(
		HANDLE ioctl_handle,
		DWORD ioctl_code,

		PVOID INPUT,
		DWORD INPUT_SIZE,

		PVOID OUTPUT,
		DWORD OUTPUT_SIZE
	);
};


#endif