#include "pch.h"
#include "NamedPipe.h"

#include <stdio.h>

HANDLE PIPE_HANDLE = NULL;

BOOLEAN ConnectPIPE_Server() {
    PIPE_HANDLE = CreateFileW(
        PIPE_NAME,
        GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        0,
        NULL
    );

    if (PIPE_HANDLE == INVALID_HANDLE_VALUE) {
        printf("PIPE ����\n");
        PIPE_HANDLE = NULL;
        return FALSE;
    }

    printf("PIPE ������ ���� ����\n");
    return TRUE;
}

BOOLEAN SendData(const void* data, DWORD dataSize) {
    if (PIPE_HANDLE == NULL) {
        printf("PIPE �ڵ� ����, �翬�� �õ�\n");
        if (!ConnectPIPE_Server()) {
            printf("�翬�� ����\n");
            return FALSE;
        }
    }

    DWORD bytesWritten = 0;
    BOOL result = WriteFile(
        PIPE_HANDLE,
        data,
        dataSize,
        &bytesWritten,
        NULL
    );

    if (!result || bytesWritten != dataSize) {
        printf("WriteFile ���� �Ǵ� ���� ũ�� ����ġ, �ڵ� �ݰ� �翬�� �õ�\n");
        CloseHandle(PIPE_HANDLE);
        PIPE_HANDLE = NULL;

        if (!ConnectPIPE_Server()) {
            printf("�翬�� ����\n");
            return FALSE;
        }

        // �翬�� �� ������ �õ�
        result = WriteFile(
            PIPE_HANDLE,
            data,
            dataSize,
            &bytesWritten,
            NULL
        );

        if (!result || bytesWritten != dataSize) {
            printf("������ ����\n");
            PIPE_HANDLE = NULL;
            return FALSE;
        }
    }

    return TRUE;
}

void ClosePIPE() {
    if (PIPE_HANDLE != NULL) {
        CloseHandle(PIPE_HANDLE);
        PIPE_HANDLE = NULL;
    }
}
