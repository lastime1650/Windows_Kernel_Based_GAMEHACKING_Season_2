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
	PUCHAR Detected_Address; // 스캔된 주소

	PUCHAR NextNode; // 다음 노드 주소
}ScanNode, * PScanNode;


/*

	INPUT to Kernel

*/
typedef struct NewScan {

	HANDLE RequesterPID; // IOCTL 요청자 PID
	HANDLE TargetPID; // 타겟


	PUCHAR value; // 스캔할 값 ( 가상주소 ) 
	SIZE_T value_size; // 스캔할 값의 크기


	PScanNode Output;

}NewScan, * PNewScan;


typedef struct AddressScanned {
	
	BOOLEAN is_same;

	PUCHAR current_value; // 현재 값
	SIZE_T current_value_size; // 

}AddressScanned, *PAddressScanned;

typedef struct AddressScan {

	HANDLE RequesterPID; // IOCTL 요청자 PID
	HANDLE TargetPID; // 타겟


	PUCHAR TargetAddress; // 지정된 주소

	PUCHAR value; // 스캔할 값 ( 가상주소 )
	SIZE_T value_size; // 스캔할 값의 크기


	PAddressScanned Output;

}AddressScan, * PAddressScan;



/*

	 AllScan은 고정 길이만큼 덤프를 모두 딴다.
	 단, 모든 PAGE가 아닌, PAGE_READWRITE부근에만.

	 지연이 상당하므로, 최초 스캐닝시 용이.
*/


typedef struct AllScannedNode {

	PUCHAR Target_Address; // 타겟 주소 ( Just Address ! )
	PUCHAR value; // 동적 할당된 공간 ( Real Data ) 
	// SIZE_T value_size; -> 메모리 사용량을 줄이기 위해 value_size는 생략.

	PUCHAR NextNode;

}AllScannedNode, *PAllScannedNode;

typedef struct AllScan {

	HANDLE RequesterPID; // IOCTL 요청자 PID
	HANDLE TargetPID; // 타겟

	SIZE_T value_size;

	PAllScannedNode Output;

}AllScan, *PAllScan;




#endif