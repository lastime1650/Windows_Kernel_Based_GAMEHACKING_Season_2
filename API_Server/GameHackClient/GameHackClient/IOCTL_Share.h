#ifndef IOCTL_SHARE_H
#define IOCTL_SHARE_H

#include <Windows.h>
#include <winioctl.h>

#define SYMBOLIC_NAME L"\\??\\NewGameHack"

#define IOCTL_NEWSCAN \
	CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1651, METHOD_BUFFERED, FILE_ANY_ACCESS) // NewScan ( First ) 

typedef struct ScanNode {
	PUCHAR Detected_Address; // ��ĵ�� �ּ�

	PUCHAR NextNode; // ���� ��� �ּ�
}ScanNode, * PScanNode;
typedef struct NewScan {

	HANDLE RequesterPID; // IOCTL ��û�� PID
	HANDLE TargetPID; // Ÿ��


	PUCHAR value; // ��ĵ�� �� ( �����ּ� ) 
	SIZE_T value_size; // ��ĵ�� ���� ũ��


	PScanNode Output;

}NewScan, * PNewScan;


#define IOCTL_TARGETSCAN \
	CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1652, METHOD_BUFFERED, FILE_ANY_ACCESS) // NextScan ( Address & value Match ) 
typedef struct AddressScanned {

	BOOLEAN is_same;

	PUCHAR current_value; // ���� ��
	SIZE_T current_value_size; // 

}AddressScanned, * PAddressScanned;

typedef struct AddressScan {

	HANDLE RequesterPID; // IOCTL ��û�� PID
	HANDLE TargetPID; // Ÿ��


	PUCHAR TargetAddress; // ������ �ּ�

	PUCHAR value; // ��ĵ�� �� ( �����ּ� )
	SIZE_T value_size; // ��ĵ�� ���� ũ��


	PAddressScanned Output;

}AddressScan, * PAddressScan;



#define IOCTL_MEMDUMP \
	CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1653, METHOD_BUFFERED, FILE_ANY_ACCESS) // Memory Page Dump

typedef struct MemDumpOutput {

	PUCHAR Dumped_StartAddress; // need free if you done using

	/*

		������ ����

	*/
	PUCHAR Dumped_PAGE_BasedAddress; // need free if you done using


	PUCHAR PAGE_BaseAddress;
	SIZE_T PAGE_Size;

	ULONG32 PAGE_Protect;
	ULONG32 PAGE_State;

}MemDumpOutput, * PMemDumpOutput;

typedef struct MemDump {

	HANDLE RequesterPID; // IOCTL ��û�� PID
	HANDLE TargetPID; // Ÿ��

	PUCHAR StartAddress; // ���� �ּ�
	SIZE_T Size; // ������ ũ��


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

	HANDLE RequesterPID; // IOCTL ��û�� PID
	HANDLE TargetPID; // Ÿ��


	PUCHAR TargetAddress; // ������ �ּ�

	PUCHAR value; // �ٲ� �� ( �����ּ� )
	SIZE_T value_size; // �ٲ� ���� ũ��

	BOOLEAN is_Protect_Change_Enable; // �������, ��ȣ�Ӽ��� PAGE_EXECUTE_READWRITE�� ���� ��ȯ ��, COPY�� ��ȣ�Ӽ� ����ó�� 

	PUCHAR Output;

}MemWrite, * PMemWrite;


#define IOCTL_MEMALLSCAN \
	CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1657, METHOD_BUFFERED, FILE_ANY_ACCESS) // Memory ALL SCAN 

typedef struct AllScannedNode {

	PUCHAR Target_Address; // Ÿ�� �ּ� ( Just Address ! )
	PUCHAR value; // ���� �Ҵ�� ���� ( Real Data ) 
	// SIZE_T value_size; -> �޸� ��뷮�� ���̱� ���� value_size�� ����.

	PUCHAR NextNode;

}AllScannedNode, * PAllScannedNode;

typedef struct AllScan {

	HANDLE RequesterPID; // IOCTL ��û�� PID
	HANDLE TargetPID; // Ÿ��

	SIZE_T value_size;

	PAllScannedNode Output;

}AllScan, * PAllScan;


#endif