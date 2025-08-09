#ifndef MEM_WRITE_H
#define MEM_WRITE_H

#include <ntifs.h>

typedef struct MemWrite {

	HANDLE RequesterPID; // IOCTL 요청자 PID
	HANDLE TargetPID; // 타겟


	PUCHAR TargetAddress; // 지정된 주소

	PUCHAR value; // 바꿀 값 ( 가상주소 )
	SIZE_T value_size; // 바꿀 값의 크기

	BOOLEAN is_Protect_Change_Enable; // 덮어쓰기전, 보호속성을 PAGE_EXECUTE_READWRITE로 강제 변환 후, COPY후 보호속성 복귀처리 

	PUCHAR Output;

}MemWrite, * PMemWrite;


#endif