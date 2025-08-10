#ifndef SHARE_STRUCT_SCAN
#define SHARE_STRUCT_SCAN

/*

	UserMode(Reuqester) <-> KernelMode(Driver) Memory Scan Structs

*/

#include <ntifs.h>

/*

	OUTPUT from Kernel

*/
typedef struct ScanNode {
	PUCHAR Detected_Address; // ��ĵ�� �ּ�

	PUCHAR NextNode; // ���� ��� �ּ�
}ScanNode, * PScanNode;


/*

	INPUT to Kernel

*/
typedef struct NewScan {

	HANDLE RequesterPID; // IOCTL ��û�� PID
	HANDLE TargetPID; // Ÿ��


	PUCHAR value; // ��ĵ�� �� ( �����ּ� ) 
	SIZE_T value_size; // ��ĵ�� ���� ũ��


	PScanNode Output;

}NewScan, * PNewScan;


typedef struct AddressScanned {
	
	BOOLEAN is_same;

	PUCHAR current_value; // ���� ��
	SIZE_T current_value_size; // 

}AddressScanned, *PAddressScanned;

typedef struct AddressScan {

	HANDLE RequesterPID; // IOCTL ��û�� PID
	HANDLE TargetPID; // Ÿ��


	PUCHAR TargetAddress; // ������ �ּ�

	PUCHAR value; // ��ĵ�� �� ( �����ּ� )
	SIZE_T value_size; // ��ĵ�� ���� ũ��


	PAddressScanned Output;

}AddressScan, * PAddressScan;



/*

	 AllScan�� ���� ���̸�ŭ ������ ��� ����.
	 ��, ��� PAGE�� �ƴ�, PAGE_READWRITE�αٿ���.

	 ������ ����ϹǷ�, ���� ��ĳ�׽� ����.
*/


typedef struct AllScannedNode {

	PUCHAR Target_Address; // Ÿ�� �ּ� ( Just Address ! )
	PUCHAR value; // ���� �Ҵ�� ���� ( Real Data ) 
	// SIZE_T value_size; -> �޸� ��뷮�� ���̱� ���� value_size�� ����.

	PUCHAR NextNode;

}AllScannedNode, *PAllScannedNode;

typedef struct AllScan {

	HANDLE RequesterPID; // IOCTL ��û�� PID
	HANDLE TargetPID; // Ÿ��

	SIZE_T value_size;

	PAllScannedNode Output;

}AllScan, *PAllScan;




#endif