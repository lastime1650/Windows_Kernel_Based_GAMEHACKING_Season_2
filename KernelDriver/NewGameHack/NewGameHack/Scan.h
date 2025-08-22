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
	
	int compared; // -1 이하: 두번쨰 인자값이 더 크다. 0: 둘 같다. 1 이상: 첫번쨰 인자값 더 크다. 

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



/*
	PointerScan
*/



typedef struct Pointers_ {

	LONG_PTR pointer; // pointer address

}Pointers, *PPointers;

typedef struct PointerScannedNode_ {


	WCHAR ImageName[260]; // allocated

	PUCHAR ImageBaseAddress; // 이미지 베이스
	ULONG_PTR ImageBaseOffset; // 이미지 베이스에 붙은 "오프셋"

	SIZE_T PointerDepth;

	PPointers NodeArray;// 포인터 동적할당형 배열 ( 인덱스로 탐색 )

	PUCHAR NextAddress;

}PointerScannedNode, *PPointerScannedNode;

typedef struct _PointerScan {
	// 입력 파라미터
	HANDLE RequesterPID;
	HANDLE TargetPID;

	PVOID  TargetAddress;

	UINT32 MaxDepth;
	UINT32 NumThreads;

	LONG_PTR MaxBaseOffset;
	LONG_PTR MaxChainOffset;

	UINT32 MinPointersInPeek; // 포인터 유효성 검사 옵션 추가



	// 출력 파라미터
	PPointerScannedNode Output;
} PointerScan, * PPointerScan;


#endif