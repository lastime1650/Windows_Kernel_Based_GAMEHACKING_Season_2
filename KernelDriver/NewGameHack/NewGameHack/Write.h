#ifndef MEM_WRITE_H
#define MEM_WRITE_H

#include <ntifs.h>

typedef struct MemWrite {

	HANDLE RequesterPID; // IOCTL ��û�� PID
	HANDLE TargetPID; // Ÿ��


	PUCHAR TargetAddress; // ������ �ּ�

	PUCHAR value; // �ٲ� �� ( �����ּ� )
	SIZE_T value_size; // �ٲ� ���� ũ��

	BOOLEAN is_Protect_Change_Enable; // �������, ��ȣ�Ӽ��� PAGE_EXECUTE_READWRITE�� ���� ��ȯ ��, COPY�� ��ȣ�Ӽ� ����ó�� 

	PUCHAR Output;

}MemWrite, * PMemWrite;


#endif