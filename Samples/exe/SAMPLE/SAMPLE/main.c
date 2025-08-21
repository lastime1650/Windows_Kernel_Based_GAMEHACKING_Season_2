#include <Windows.h>
#include <stdio.h>

// ------------------- 추가된 구조체 -------------------
typedef struct B {
    BYTE padding[0x10];  // 0x10 바이트 패딩
    DWORD hp;            // +0x10
} B;

typedef struct A {
    BYTE padding[0x20];  // 0x20 바이트 패딩
    B b;                 // +0x20
} A;

typedef struct NODE {
    BYTE padding[0x1];  // +0xAB 오프셋에 next 포인터 존재
    void* next;
} NODE;

// ------------------- 전역 루트 -------------------
void* gRoot = NULL;

// ------------------- HP 초기화 함수 -------------------
void InitWorld(void) {
    A* a = (A*)malloc(sizeof(A));
    ZeroMemory(a, sizeof(A));
    a->b.hp = 100;

    NODE* nodes[6];
    for (int i = 0; i < 6; i++) {
        nodes[i] = (NODE*)malloc(sizeof(NODE));
        ZeroMemory(nodes[i], sizeof(NODE));
    }

    for (int i = 0; i < 5; i++) {
        *(void**)((uintptr_t)nodes[i] + 0xAB) = nodes[i + 1];
    }
    *(void**)((uintptr_t)nodes[5] + 0xAB) = a;

    gRoot = nodes[0];
}

void* TraverseHP(void) {
    void* n = gRoot;
    for (int i = 0; i < 6; i++) {
        n = *(void**)((uintptr_t)n + 0xAB);
    }
    A* a = (A*)n;
    return &(a->b.hp);
}

// ------------------- 기존 코드 -------------------
HANDLE IOCTL_HANDLE = NULL;

#define BUFFER_SIZE sizeof(CONTEXT) // context 그대로 받기
VOID Pipe_Receive_Thread(PHANDLE PIPE_HANDLE);

DWORD GlobalDWORD = 0;
PDWORD Global_Pointer_DWORD = NULL;
DWORD*** Global_Tripple_Pointer_DWORD = NULL;
DWORD** Global_Pointer_Arrary_DWORD = NULL;
SIZE_T Global_Pointer_Arrary_DWORD_SIZE = sizeof(DWORD) * 12;

#define SYMBOLIC_NAME L"\\??\\NewGameHack"

int main() {

    InitWorld();
    PDWORD hpAddr = (PDWORD)TraverseHP();

    printf("Process ID: %lu\n", GetCurrentProcessId());

    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    if (hKernel32 == NULL) {
        printf("Failed to get handle for kernel32.dll\n");
        return 1;
    }

    FARPROC pLoadLibraryA = GetProcAddress(hKernel32, "LoadLibraryA");
    if (pLoadLibraryA == NULL) {
        printf("Failed to get address for LoadLibraryA\n");
        return 1;
    }

    printf("Kernel32.dll Address: %p\n", hKernel32);
    printf("LoadLibraryA Address: %p\n\n", pLoadLibraryA);

    printf("자신의 ThreadID: %d\n", GetCurrentThreadId());
    HANDLE hCurrentThread = GetCurrentThread();
    HANDLE hDupThread = NULL;

    BOOL success = DuplicateHandle(
        GetCurrentProcess(),
        hCurrentThread,
        GetCurrentProcess(),
        &hDupThread,
        THREAD_ALL_ACCESS,
        FALSE,
        0
    );
    printf("일반-스레드핸들 %d\n", hCurrentThread);
    printf("외부 참조 가능한 ThreadHandle %p\n", hDupThread);

    printf("SuspendThread Address: %p\n", GetProcAddress(hKernel32, "SuspendThread"));
    printf("ResumeThread Address: %p\n\n\n", GetProcAddress(hKernel32, "ResumeThread"));

    ULONG32 value1 = 0;
    FLOAT value2 = 0.1f;
    DOUBLE value3 = 0.01;
    Global_Pointer_DWORD = malloc(sizeof(DWORD));
    *Global_Pointer_DWORD = 0;

    PDWORD original = malloc(sizeof(DWORD));
    *original = 0;
    PDWORD* To_Original_A = malloc(sizeof(PDWORD));
    *To_Original_A = original;
    Global_Tripple_Pointer_DWORD = malloc(sizeof(PDWORD*));
    *Global_Tripple_Pointer_DWORD = To_Original_A;

    Global_Pointer_Arrary_DWORD = (PDWORD*)malloc(Global_Pointer_Arrary_DWORD_SIZE);
    for (int i = 0; i < (Global_Pointer_Arrary_DWORD_SIZE / 4); i++) {
        PDWORD my_data = (PDWORD)malloc(4);
        *my_data = (i + 1);
        Global_Pointer_Arrary_DWORD[i] = my_data;
    }

    while (1) {
        value1 += 1;
        value2 += 0.1f;
        value3 += 0.01;
        GlobalDWORD += 5;
        *Global_Pointer_DWORD += 10;
        ***Global_Tripple_Pointer_DWORD += 100;

        // HP 로직 추가
        printf("[HP] Addr: %p -> %d\n\n", hpAddr, *hpAddr);
        *hpAddr += 1;

        printf("GlobalDWORD:(%p}: %lu, Global_Pointer_DWORD: (%p): %lu, Global_DoublePointer_DWORD: (%p): %lu,\n"
            "Value1(%p): %lu, Value2(%p): %.2f, Value3(%p): %.2f\n\n",
            &GlobalDWORD, GlobalDWORD,
            Global_Pointer_DWORD, *Global_Pointer_DWORD,
            Global_Tripple_Pointer_DWORD, ***Global_Tripple_Pointer_DWORD,
            &value1, value1,
            &value2, value2,
            &value3, value3
        );

        CONTEXT ctx;
        ctx.ContextFlags = CONTEXT_FULL;
        if (GetThreadContext(hCurrentThread, &ctx)) {
            printf("DR0 = 0x%llx\n", ctx.Dr0);
            printf("DR1 = 0x%llx\n", ctx.Dr1);
            printf("DR2 = 0x%llx\n", ctx.Dr2);
            printf("DR3 = 0x%llx\n", ctx.Dr3);
            printf("DR6 = 0x%llx\n", ctx.Dr6);
            printf("DR7 = 0x%llx\n", ctx.Dr7);
        }
        else {
            printf("GetThreadContext failed. Error: %lu\n", GetLastError());
        }

        system("pause");
    }
    return 0;
}

VOID Pipe_Receive_Thread(PHANDLE PIPE_HANDLE) {
    HANDLE hPipe = CreateNamedPipe(
        L"\\\\.\\pipe\\ContextPipe",
        PIPE_ACCESS_INBOUND,
        PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
        1,
        BUFFER_SIZE,
        BUFFER_SIZE,
        0,
        NULL
    );

    printf("NamedPIPE 클라이언트 대기중..\n");
    ConnectNamedPipe(hPipe, NULL);
    printf("NamedPIPE 클라이언트 연결됨..\n");

    DWORD bytesRead = 0;
    char BUFFER[BUFFER_SIZE] = { 0, };
    while (ReadFile(hPipe, BUFFER, BUFFER_SIZE, &bytesRead, NULL)) {
        printf("PIPE 데이터 수신됨 크기: %d\n", bytesRead);
        PCONTEXT context = (PCONTEXT)&BUFFER;
        printf("[TEST] context - %p\n", context->Dr6);
    }
}
