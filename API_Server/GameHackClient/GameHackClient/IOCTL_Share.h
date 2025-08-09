#ifndef IOCTL_SHARE_H
#define IOCTL_SHARE_H

#include <Windows.h>
#include <winioctl.h>

#define SYMBOLIC_NAME L"\\??\\NewGameHack"

#define IOCTL_NEWSCAN \
	CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1651, METHOD_BUFFERED, FILE_ANY_ACCESS) // NewScan ( First ) 

typedef struct ScanNode {
	PUCHAR Detected_Address; // 스캔된 주소

	PUCHAR NextNode; // 다음 노드 주소
}ScanNode, * PScanNode;
typedef struct NewScan {

	HANDLE RequesterPID; // IOCTL 요청자 PID
	HANDLE TargetPID; // 타겟


	PUCHAR value; // 스캔할 값 ( 가상주소 ) 
	SIZE_T value_size; // 스캔할 값의 크기


	PScanNode Output;

}NewScan, * PNewScan;


#define IOCTL_TARGETSCAN \
	CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1652, METHOD_BUFFERED, FILE_ANY_ACCESS) // NextScan ( Address & value Match ) 
typedef struct AddressScanned {

	BOOLEAN is_same;

	PUCHAR current_value; // 현재 값
	SIZE_T current_value_size; // 

}AddressScanned, * PAddressScanned;

typedef struct AddressScan {

	HANDLE RequesterPID; // IOCTL 요청자 PID
	HANDLE TargetPID; // 타겟


	PUCHAR TargetAddress; // 지정된 주소

	PUCHAR value; // 스캔할 값 ( 가상주소 )
	SIZE_T value_size; // 스캔할 값의 크기


	PAddressScanned Output;

}AddressScan, * PAddressScan;



#define IOCTL_MEMDUMP \
	CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1653, METHOD_BUFFERED, FILE_ANY_ACCESS) // Memory Page Dump

typedef struct MemDumpOutput {

	PUCHAR Dumped_StartAddress; // need free if you done using

	/*

		페이지 정보

	*/
	PUCHAR Dumped_PAGE_BasedAddress; // need free if you done using


	PUCHAR PAGE_BaseAddress;
	SIZE_T PAGE_Size;

	ULONG32 PAGE_Protect;
	ULONG32 PAGE_State;

}MemDumpOutput, * PMemDumpOutput;

typedef struct MemDump {

	HANDLE RequesterPID; // IOCTL 요청자 PID
	HANDLE TargetPID; // 타겟

	PUCHAR StartAddress; // 시작 주소
	SIZE_T Size; // 덤프할 크기


	PMemDumpOutput Output;
}MemDump, * PMemDump;



#define IOCTL_DLLINJECTION \
	CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1654, METHOD_BUFFERED, FILE_ANY_ACCESS) // DLL Injection

typedef struct DLL_INJECTION_IOCTL {
	HANDLE ProcessId; // Target Process ID
	CHAR Injection_Dll_PATH[265]; // DLL PATH ( ANSI ) 

	NTSTATUS Output; // output status

} DLL_INJECTION_INPUT, * PDLL_INJECTION_INPUT;


#define IOCTL_HardwareBP \
	CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1655, METHOD_BUFFERED, FILE_ANY_ACCESS) // DLL Injection

typedef struct Hardware_Breakpoint {

	BOOLEAN is_remove; // if TRUE, remove. if FALSE, add

	HANDLE TargetPID;
	PUCHAR TargetAddress;

	NTSTATUS Output;

}Hardware_Breakpoint, * PHardware_Breakpoint;




#define IOCTL_MEMWRITE \
	CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1656, METHOD_BUFFERED, FILE_ANY_ACCESS) // DLL Injection

typedef struct MemWrite {

	HANDLE RequesterPID; // IOCTL 요청자 PID
	HANDLE TargetPID; // 타겟


	PUCHAR TargetAddress; // 지정된 주소

	PUCHAR value; // 바꿀 값 ( 가상주소 )
	SIZE_T value_size; // 바꿀 값의 크기

	BOOLEAN is_Protect_Change_Enable; // 덮어쓰기전, 보호속성을 PAGE_EXECUTE_READWRITE로 강제 변환 후, COPY후 보호속성 복귀처리 

	PUCHAR Output;

}MemWrite, * PMemWrite;


#define IOCTL_MEMALLSCAN \
	CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1657, METHOD_BUFFERED, FILE_ANY_ACCESS) // Memory ALL SCAN 

typedef struct AllScannedNode {

	PUCHAR Target_Address; // 타겟 주소 ( Just Address ! )
	PUCHAR value; // 동적 할당된 공간 ( Real Data ) 
	// SIZE_T value_size; -> 메모리 사용량을 줄이기 위해 value_size는 생략.

	PUCHAR NextNode;

}AllScannedNode, * PAllScannedNode;

typedef struct AllScan {

	HANDLE RequesterPID; // IOCTL 요청자 PID
	HANDLE TargetPID; // 타겟

	SIZE_T value_size;

	PAllScannedNode Output;

}AllScan, * PAllScan;


#endif