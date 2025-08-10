// dllmain.cpp : DLL 애플리케이션의 진입점을 정의합니다.
#include "pch.h"
#include <stdio.h>

#include "NamedPipe.h"

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    {
        // NamedPipe 서버에 연결
        BOOLEAN PIPE_bool = ConnectPIPE_Server();
        printf("PIPE status %d\n", PIPE_bool);

        // 하드웨어 브레이크포인트 핸들러 
        BOOLEAN VEH_Handler_bool = VEH_Handler();
        printf("VEH status %d\n", VEH_Handler_bool);

        break;
    }
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

