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
        printf("PIPE 없음\n");
        PIPE_HANDLE = NULL;
        return FALSE;
    }

    printf("PIPE 서버에 연결 성공\n");
    return TRUE;
}

BOOLEAN SendData(const void* data, DWORD dataSize) {
    if (PIPE_HANDLE == NULL) {
        printf("PIPE 핸들 없음, 재연결 시도\n");
        if (!ConnectPIPE_Server()) {
            printf("재연결 실패\n");
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
        printf("WriteFile 실패 또는 전송 크기 불일치, 핸들 닫고 재연결 시도\n");
        CloseHandle(PIPE_HANDLE);
        PIPE_HANDLE = NULL;

        if (!ConnectPIPE_Server()) {
            printf("재연결 실패\n");
            return FALSE;
        }

        // 재연결 후 재전송 시도
        result = WriteFile(
            PIPE_HANDLE,
            data,
            dataSize,
            &bytesWritten,
            NULL
        );

        if (!result || bytesWritten != dataSize) {
            printf("재전송 실패\n");
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
